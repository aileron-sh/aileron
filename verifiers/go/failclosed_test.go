package aileron

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/aileron-sh/aileron/verifiers/go/canonical"
)

// These tests pin the fix for the Go verifier failing open. Its reader used to
// treat any read error as the end of the journal, so Verify on a directory
// returned OK with 0 events, and a journal it had no permission to read came
// out as TAMPERED at seq None with exit 2, where the Python CLI exits 1. A
// journal or checkpoints file that exists but cannot be read is now an
// operational error: the library returns an error and no verdict, and the
// command line prints one error line and exits 1, never OK and never TAMPERED.

// requireOperationalError runs args through the command line and checks the
// outcome is an operational error: exit 1, exactly one "error: " line, and it
// mentions want, with no OK, TAMPERED or FAILED verdict anywhere.
func requireOperationalError(t *testing.T, args []string, want string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Run(args, &out, &errOut)
	stdout, stderr := out.String(), errOut.String()
	if code != 1 {
		t.Fatalf("%q: exit %d, want 1\nstdout: %s\nstderr: %s", args, code, stdout, stderr)
	}
	if strings.Contains(stdout, "OK:") || strings.Contains(stderr, "TAMPERED") || strings.Contains(stderr, "FAILED") {
		t.Fatalf("%q: an operational error must not print a verdict\nstdout: %s\nstderr: %s", args, stdout, stderr)
	}
	var errorLines []string
	for _, line := range strings.Split(strings.TrimRight(stderr, "\n"), "\n") {
		if strings.HasPrefix(line, "error: ") {
			errorLines = append(errorLines, line)
		}
	}
	if len(errorLines) != 1 || !strings.Contains(errorLines[0], want) {
		t.Fatalf("%q: want one error line mentioning %q, stderr:\n%s", args, want, stderr)
	}
}

// requireNoVerdict checks that a failed Verify carries nothing a careless
// caller could mistake for a verdict.
func requireNoVerdict(t *testing.T, result VerifyResult, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("want an error, got verdict %+v", result)
	}
	if result.OK || result.Count != 0 || result.FirstBadSeq != nil || result.Errors != nil {
		t.Fatalf("an operational error must come with the zero VerifyResult, got %+v", result)
	}
}

// makeUnreadable takes every permission off path for the rest of the test, or
// skips the test where permission bits do not stop the current user.
func makeUnreadable(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("permission bits do not stop reads on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root, which reads files and searches directories regardless of their mode")
	}
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(path, 0o755) }) // so the temporary directory can be removed
	if f, err := os.Open(path); err == nil {
		f.Close()
		t.Skipf("%s can still be opened after chmod 0", path)
	}
}

// signedJournal writes a three-event journal with one valid checkpoint and
// returns the journal path and the public key path.
func signedJournal(t *testing.T) (journal, key string) {
	t.Helper()
	s := newSigner(t)
	journal = filepath.Join(s.dir, "j.jsonl")
	_, hashes := writeChain(t, journal, 3)
	ck, _ := s.checkpoint(t, "1", GenesisPrevHash, "3", hashes[2])
	if err := os.WriteFile(CheckpointsPath(journal), []byte(ck+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	key = filepath.Join(s.dir, PublicKeyName)
	if valid, err := VerifyCheckpoint(journal, key); err != nil || !valid {
		t.Fatalf("setup: the untouched journal should verify: %v %v", valid, err)
	}
	return journal, key
}

func TestVerifyDirectoryIsAnOperationalError(t *testing.T) {
	journal := filepath.Join(t.TempDir(), "j.jsonl")
	if err := os.Mkdir(journal, 0o755); err != nil {
		t.Fatal(err)
	}
	result, err := Verify(journal)
	requireNoVerdict(t, result, err)
	if !errors.Is(err, errIsDirectory) {
		t.Fatalf("Verify on a directory: %v", err)
	}
	requireOperationalError(t, []string{"verify", journal}, "is a directory")
	if _, err := ReadEvents(journal); !errors.Is(err, errIsDirectory) {
		t.Fatalf("ReadEvents on a directory: %v", err)
	}

	// The reader itself, not only the check up front. Reading a directory
	// fails on these platforms, and that failure used to end the loop as if
	// the journal were empty, which is how Verify came to say OK.
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		f, err := os.Open(journal)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		result, err := verifyReader(f)
		requireNoVerdict(t, result, err)
	}
}

func TestVerifyCheckpointWithDirectoryJournalIsAnOperationalError(t *testing.T) {
	// Valid signed checkpoints next to a journal that has become a directory:
	// the checkpoints hold up, so the journal is read, and that read fails.
	// Python raises there; reporting FAILED would claim a verdict nobody has.
	journal, key := signedJournal(t)
	if err := os.Remove(journal); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(journal, 0o755); err != nil {
		t.Fatal(err)
	}
	if valid, err := VerifyCheckpoint(journal, key); valid || !errors.Is(err, errIsDirectory) {
		t.Fatalf("VerifyCheckpoint: valid=%v err=%v, want an is-a-directory error", valid, err)
	}
	requireOperationalError(t, []string{"verify-checkpoint", journal, "--key", key}, "is a directory")
}

func TestCheckpointsFileThatIsADirectoryIsAnOperationalError(t *testing.T) {
	journal, key := signedJournal(t)
	if err := os.Remove(CheckpointsPath(journal)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(CheckpointsPath(journal), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCheckpoints(journal); !errors.Is(err, errIsDirectory) {
		t.Fatalf("ReadCheckpoints: %v", err)
	}
	if _, err := CheckAgainstCheckpoints(journal); !errors.Is(err, errIsDirectory) {
		t.Fatalf("CheckAgainstCheckpoints: %v", err)
	}
	requireOperationalError(t, []string{"verify", journal}, "is a directory")
	requireOperationalError(t, []string{"verify-checkpoint", journal, "--key", key}, "is a directory")
}

func TestVerifyUnreadableJournalIsAnOperationalError(t *testing.T) {
	journal, key := signedJournal(t)
	makeUnreadable(t, journal)

	result, err := Verify(journal)
	requireNoVerdict(t, result, err)
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("Verify: %v, want a permission error", err)
	}
	// This printed "TAMPERED at seq None" and exited 2.
	requireOperationalError(t, []string{"verify", journal}, "permission denied")

	if _, err := ReadEvents(journal); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("ReadEvents: %v", err)
	}
	if _, err := CheckAgainstCheckpoints(journal); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("CheckAgainstCheckpoints: %v", err)
	}
	if valid, err := VerifyCheckpoint(journal, key); valid || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("VerifyCheckpoint: valid=%v err=%v", valid, err)
	}
	requireOperationalError(t, []string{"verify-checkpoint", journal, "--key", key}, "permission denied")
}

func TestUnreadableCheckpointsFileIsAnOperationalError(t *testing.T) {
	journal, key := signedJournal(t)
	makeUnreadable(t, CheckpointsPath(journal))

	if _, err := ReadCheckpoints(journal); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("ReadCheckpoints: %v, want a permission error rather than no checkpoints", err)
	}
	requireOperationalError(t, []string{"verify", journal}, "permission denied")
	requireOperationalError(t, []string{"verify-checkpoint", journal, "--key", key}, "permission denied")
	// --skip-checkpoint-check does not read the file at all.
	var out, errOut bytes.Buffer
	if code := Run([]string{"verify", journal, "--skip-checkpoint-check"}, &out, &errOut); code != 0 {
		t.Fatalf("--skip-checkpoint-check: exit %d\n%s", code, errOut.String())
	}
}

// A journal the verifier cannot even stat, here because its directory may not
// be searched, counts as missing. That is not this package's preference but
// Python's: the reference checks os.path.exists first, which is false for any
// path stat fails on, and so reports "log file not found" with exit 2. Doing
// otherwise here would make the two verifiers disagree on the exit code.
func TestVerifyJournalInUnsearchableDirectoryCountsAsMissing(t *testing.T) {
	s := newSigner(t) // the key stays in its own, readable directory
	dir := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(dir, "j.jsonl")
	_, hashes := writeChain(t, journal, 1)
	ck, _ := s.checkpoint(t, "1", GenesisPrevHash, "1", hashes[0])
	if err := os.WriteFile(CheckpointsPath(journal), []byte(ck+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	makeUnreadable(t, dir)

	result, err := Verify(journal)
	if err != nil {
		t.Fatalf("a journal that cannot be stat'ed is reported as missing, not as an error: %v", err)
	}
	if result.OK || len(result.Errors) != 1 || result.Errors[0] != "log file not found: "+journal {
		t.Fatalf("unexpected result: %+v", result)
	}
	var out, errOut bytes.Buffer
	if code := Run([]string{"verify", journal}, &out, &errOut); code != 2 ||
		!strings.HasSuffix(errOut.String(), "TAMPERED at seq None in "+journal+"\n") {
		t.Fatalf("exit %d, stderr %q", code, errOut.String())
	}

	// verify-checkpoint opens the checkpoints file first. Opening it fails for
	// a reason other than nothing being there, so that is an operational error
	// in both verifiers, not the FAILED a missing checkpoints file gets.
	requireOperationalError(t, []string{"verify-checkpoint", journal, "--key", filepath.Join(s.dir, PublicKeyName)},
		"permission denied")
}

// The checkpoints file is absent only when opening it finds nothing there. A
// checkpoints path that cannot be opened for any other reason is an
// operational error, because calling it absent skips the cross-check: verify
// printed OK here, beside a checkpoints file saying the journal had been cut.
// Python's read_checkpoints follows the same rule.
func TestCheckpointsPathThatCannotBeOpenedIsAnOperationalError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	journal, key := signedJournal(t)
	// Cut the journal below its checkpoint, so only the cross-check can tell.
	data, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(data), "\n")
	if err := os.WriteFile(journal, []byte(lines[0]+lines[1]), 0o644); err != nil {
		t.Fatal(err)
	}
	ck := CheckpointsPath(journal)
	private := filepath.Join(filepath.Dir(journal), "private")
	if err := os.Mkdir(private, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(ck, filepath.Join(private, "ck.jsonl")); err != nil {
		t.Fatal(err)
	}
	relink := func(target string) {
		t.Helper()
		if err := os.Remove(ck); err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(err)
		}
		if err := os.Symlink(target, ck); err != nil {
			t.Fatal(err)
		}
	}

	// Through a symlink that resolves, the cross-check runs and sees the cut.
	relink(filepath.Join("private", "ck.jsonl"))
	var out, errOut bytes.Buffer
	if code := Run([]string{"verify", journal}, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "appears truncated") {
		t.Fatalf("readable checkpoints: exit %d, stderr %q", code, errOut.String())
	}

	// A symlink to nothing is nothing there, so there is nothing to cross-check.
	relink("nowhere.jsonl")
	out.Reset()
	errOut.Reset()
	if code := Run([]string{"verify", journal}, &out, &errOut); code != 0 {
		t.Fatalf("dangling symlink: exit %d, stderr %q", code, errOut.String())
	}

	// A symlink loop is something there that cannot be opened.
	relink(filepath.Base(ck))
	requireOperationalError(t, []string{"verify", journal}, "too many levels of symbolic links")
	requireOperationalError(t, []string{"verify-checkpoint", journal, "--key", key}, "too many levels of symbolic links")

	// So is a symlink into a directory the verifier may not search. This comes
	// last because makeUnreadable skips the rest of the test where it cannot
	// take the permission away.
	relink(filepath.Join("private", "ck.jsonl"))
	makeUnreadable(t, private)
	requireOperationalError(t, []string{"verify", journal}, "permission denied")
}

// endless serves bytes that are not UTF-8 forever, as /dev/urandom does in
// effect, and fails once more than limit bytes have been asked of it.
type endless struct{ served, limit int }

var errReadTooFar = errors.New("kept reading past the first line that is not UTF-8")

func (r *endless) Read(p []byte) (int, error) {
	if r.served >= r.limit {
		return 0, errReadTooFar
	}
	for i := range p {
		p[i] = "\xff\n"[i%2]
	}
	r.served += len(p)
	return len(p), nil
}

// Python reads the checkpoints file as text and gives up at the first byte
// that is not UTF-8. Reading the whole file before checking it meant a
// checkpoints path that led to a device never finished, so this must stop at
// the first bad line too.
func TestReadCheckpointsStopsAtTheFirstInvalidByte(t *testing.T) {
	r := &endless{limit: 1 << 20}
	cks, err := readCheckpoints(r)
	if cks != nil || err == nil || errors.Is(err, errReadTooFar) ||
		!strings.Contains(err.Error(), "can't decode byte 0xff in position 0") {
		t.Fatalf("readCheckpoints = %d checkpoints, %v; want the UTF-8 error from the first line", len(cks), err)
	}

	// Positions count from the start of the file, not of the line.
	_, err = readCheckpoints(strings.NewReader("{\"a\":1}\n{\"b\":\"\xff\"}\n"))
	if err == nil || !strings.Contains(err.Error(), "in position 14") {
		t.Fatalf("second-line error: %v", err)
	}
}

// failingReader serves the first n bytes of data and then fails with err on
// every call. With together set, the call that reaches n returns its last
// bytes and err at once, which io.Reader allows.
type failingReader struct {
	data     []byte
	n        int
	err      error
	together bool
	pos      int
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.pos >= r.n {
		return 0, r.err
	}
	k := copy(p, r.data[r.pos:r.n])
	r.pos += k
	if r.together && r.pos >= r.n {
		return k, r.err
	}
	return k, nil
}

func TestVerifyReadErrorPartWayIsAnOperationalError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "j.jsonl")
	lines, _ := writeChain(t, path, 3)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	endOfFirst := len(lines[0]) + 1
	boom := errors.New("input/output error")

	for _, tc := range []struct {
		name string
		n    int
	}{
		{"before any byte", 0},
		{"inside the first line", endOfFirst / 2},
		{"at the end of the first line", endOfFirst},
		{"inside the second line", endOfFirst + 10},
		{"after the last byte, in place of EOF", len(data)},
	} {
		for _, together := range []bool{false, true} {
			r := &failingReader{data: data, n: tc.n, err: boom, together: together}
			result, err := verifyReader(r)
			requireNoVerdict(t, result, err)
			if !errors.Is(err, boom) {
				t.Errorf("%s (together=%v): err = %v, want the reader's error", tc.name, together, err)
			}
			// The lenient reader behind the checkpoint checks must not hand
			// back a short list either: VerifyCheckpoint indexes into it.
			r = &failingReader{data: data, n: tc.n, err: boom, together: together}
			if events, err := readEvents(r); !errors.Is(err, boom) || events != nil {
				t.Errorf("%s (together=%v): readEvents = %d events, %v", tc.name, together, len(events), err)
			}
			// Nor the checkpoints reader: a short list there drops the newest,
			// widest checkpoints, and a journal cut below them passes as OK.
			r = &failingReader{data: data, n: tc.n, err: boom, together: together}
			if cks, err := readCheckpoints(r); !errors.Is(err, boom) || cks != nil {
				t.Errorf("%s (together=%v): readCheckpoints = %d objects, %v", tc.name, together, len(cks), err)
			}
		}
	}
	if cks, err := readCheckpoints(iotest.OneByteReader(bytes.NewReader(data))); err != nil || len(cks) != 3 {
		t.Fatalf("readCheckpoints over the whole journal: %d objects, %v", len(cks), err)
	}

	// The same bytes with a clean EOF verify, however the reads are sliced.
	want, err := verifyReader(bytes.NewReader(data))
	if err != nil || !want.OK || want.Count != 3 {
		t.Fatalf("whole journal: %+v %v", want, err)
	}
	for name, r := range map[string]io.Reader{
		"one byte at a time":   iotest.OneByteReader(bytes.NewReader(data)),
		"half reads":           iotest.HalfReader(bytes.NewReader(data)),
		"data and EOF at once": iotest.DataErrReader(bytes.NewReader(data)),
	} {
		got, err := verifyReader(r)
		if err != nil || got.OK != want.OK || got.Count != want.Count || len(got.Errors) != 0 {
			t.Errorf("%s: %+v %v", name, got, err)
		}
	}
}

// withSecondRead makes VerifyCheckpoint's second read of the journal return
// what read returns, for the rest of the test.
func withSecondRead(t *testing.T, read func(path string) ([]*canonical.Value, error)) {
	t.Helper()
	saved := readJournalEvents
	readJournalEvents = read
	t.Cleanup(func() { readJournalEvents = saved })
}

func TestVerifyCheckpointJournalThatShrinksBetweenReadsIsAnOperationalError(t *testing.T) {
	journal, key := signedJournal(t)
	// The first read sees 3 events, the second none: rotated or truncated in
	// between. This indexed the second read's events with the first read's
	// count and panicked. Neither read speaks for the journal, so no verdict.
	withSecondRead(t, func(string) ([]*canonical.Value, error) { return nil, nil })
	valid, err := VerifyCheckpoint(journal, key)
	if valid || err == nil || !strings.Contains(err.Error(), "changed while it was being verified (3 events, then 0)") {
		t.Fatalf("VerifyCheckpoint: valid=%v err=%v", valid, err)
	}
	requireOperationalError(t, []string{"verify-checkpoint", journal, "--key", key}, "changed while it was being verified")
}

func TestVerifyCheckpointJournalUnreadableOnSecondReadIsAnOperationalError(t *testing.T) {
	journal, key := signedJournal(t)
	// The second read fails outright. That is an error, not the FAILED verdict
	// this used to give about a journal it had not been able to read.
	boom := errors.New("second read failed")
	withSecondRead(t, func(string) ([]*canonical.Value, error) { return nil, boom })
	if valid, err := VerifyCheckpoint(journal, key); valid || !errors.Is(err, boom) {
		t.Fatalf("VerifyCheckpoint: valid=%v err=%v, want the second read's error", valid, err)
	}
	requireOperationalError(t, []string{"verify-checkpoint", journal, "--key", key}, "second read failed")
}
