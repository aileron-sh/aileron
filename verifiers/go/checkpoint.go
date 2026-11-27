package aileron

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/aileron-sh/aileron/verifiers/go/canonical"
)

// Standard key file names, as written by `aileron init`.
const (
	PrivateKeyName = "aileron_ed25519.key"
	PublicKeyName  = "aileron_ed25519.pub"
)

// CheckpointsPath is where checkpoints for a journal live.
func CheckpointsPath(logPath string) string { return logPath + ".checkpoints.jsonl" }

// SignedPayload is the byte string a checkpoint's signature covers: the
// canonical JSON of the checkpoint without "signature" and "pubkey_path".
func SignedPayload(checkpoint *canonical.Value) ([]byte, error) {
	return canonical.Marshal(checkpoint.Without("signature", "pubkey_path"))
}

// CheckpointHash is sha256 of the signed payload as lowercase hex. Each
// checkpoint names its predecessor's hash in prev_checkpoint_hash.
func CheckpointHash(checkpoint *canonical.Value) (string, error) {
	payload, err := SignedPayload(checkpoint)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

// ReadCheckpoints returns every checkpoint object recorded for logPath, in
// file order. Lines that are blank, not JSON, or not objects are skipped, as
// Python's reader skips them.
//
// The file is absent, an empty list, only when opening it finds nothing there,
// a symlink to nothing included. Anything else that stops it being opened or
// read to the end is an error, never an empty list: a symlink loop, a symlink
// into a directory the verifier may not search, an I/O error. Calling those
// absent would let verify skip the cross-check and print OK beside a
// checkpoints file in plain sight. Python's read_checkpoints follows the same
// rule. Invalid UTF-8 anywhere in the file is an error too: Python reads it as
// text and stops with UnicodeDecodeError, exit 1.
func ReadCheckpoints(logPath string) ([]*canonical.Value, error) {
	f, err := openForReading(CheckpointsPath(logPath))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readCheckpoints(f)
}

// readCheckpoints is ReadCheckpoints over the bytes of r. It works one line at
// a time and stops at the first read error or invalid UTF-8, as Python's text
// reader does, so a file that never ends, such as a device, is refused rather
// than read until memory runs out.
func readCheckpoints(r io.Reader) ([]*canonical.Value, error) {
	var out []*canonical.Value
	reader := bufio.NewReader(r)
	offset := 0 // of raw in the file, so the error names the same position
	for {
		raw, readErr := reader.ReadBytes('\n')
		if readErr != nil && readErr != io.EOF {
			return nil, readErr
		}
		// No byte of a UTF-8 sequence is \n or \r, so checking and splitting
		// one \n-terminated piece at a time finds what the whole file would.
		if !utf8.Valid(raw) {
			return nil, errors.New(utf8Error(raw, offset))
		}
		offset += len(raw)
		// Python opens the file in text mode, which treats \r\n and a lone \r
		// as line breaks too.
		text := strings.ReplaceAll(string(raw), "\r\n", "\n")
		text = strings.ReplaceAll(text, "\r", "\n")
		for _, line := range strings.Split(text, "\n") {
			line = canonical.Strip(line)
			if line == "" {
				continue
			}
			v, err := canonical.Parse(line)
			if err != nil || v.Kind != canonical.Object {
				continue
			}
			out = append(out, v)
		}
		if readErr != nil {
			return out, nil // io.EOF
		}
	}
}

// usableCount reports whether a checkpoint's count is what sign_checkpoint
// writes: a JSON integer (not a bool) greater than zero.
func usableCount(count *canonical.Value) (*big.Int, bool) {
	if count.Kind != canonical.Int {
		return nil, false
	}
	n := count.BigInt()
	if n.Sign() <= 0 {
		return nil, false
	}
	return n, true
}

// CheckAgainstCheckpoints cross-checks a journal against the checkpoints file
// next to it and returns the inconsistencies found; empty means consistent,
// or that there was nothing to check against.
//
// This check is unauthenticated by design, exactly as in Python: no key is
// needed for `verify`, so signatures are not examined. What it catches is a
// journal truncated or rewritten while the checkpoint file that contradicts
// it was left in place.
func CheckAgainstCheckpoints(logPath string) ([]string, error) {
	checkpoints, err := ReadCheckpoints(logPath)
	if err != nil {
		return nil, err
	}
	if len(checkpoints) == 0 {
		return nil, nil
	}
	events, err := ReadEvents(logPath)
	if err != nil {
		return nil, err
	}
	var problems []string
	for index, checkpoint := range checkpoints {
		countValue := checkpoint.Get("count")
		tip := checkpoint.Get("tip_hash")
		count, ok := usableCount(countValue)
		if !ok {
			problems = append(problems, fmt.Sprintf(
				"checkpoint %d has an unusable count (%s), so it could not be cross-checked - "+
					"the checkpoints file has been edited and this log should be treated as unverified",
				index, canonical.PyRepr(countValue)))
			continue
		}
		if tip.Kind != canonical.String {
			problems = append(problems, fmt.Sprintf(
				"checkpoint %d has an unusable tip_hash (%s), so it could not be cross-checked - "+
					"the checkpoints file has been edited and this log should be treated as unverified",
				index, canonical.PyRepr(tip)))
			continue
		}
		if big.NewInt(int64(len(events))).Cmp(count) < 0 {
			problems = append(problems, fmt.Sprintf(
				"log has %d events but a checkpoint attests to %s - the journal appears truncated",
				len(events), count))
		} else if !canonical.Equal(events[count.Int64()-1].Get("hash"), tip) {
			problems = append(problems, fmt.Sprintf(
				"event at seq %s does not match the checkpointed tip hash - the journal appears rewritten",
				count))
		}
	}
	return problems, nil
}

// LoadPublicKey loads an Ed25519 public key from keyPath: a PEM public key
// (SubjectPublicKeyInfo), a PEM PKCS#8 private key (the public half is
// derived), or a directory holding the standard key pair files, in which
// case the public key is preferred so a verifying host never needs the
// private key present.
func LoadPublicKey(keyPath string) (ed25519.PublicKey, error) {
	path := keyPath
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		path = filepath.Join(keyPath, PublicKeyName)
		if _, err := os.Stat(path); err != nil {
			path = filepath.Join(keyPath, PrivateKeyName)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM data found in %s", keyPath)
	}
	if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if key, ok := pub.(ed25519.PublicKey); ok {
			return key, nil
		}
		return nil, fmt.Errorf("not an ed25519 key: %s", keyPath)
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse key %s: %w", keyPath, err)
	}
	if key, ok := priv.(ed25519.PrivateKey); ok {
		return key.Public().(ed25519.PublicKey), nil
	}
	return nil, fmt.Errorf("not an ed25519 key: %s", keyPath)
}

// readJournalEvents is ReadEvents. VerifyCheckpoint reads the journal twice,
// once through Verify and once through this, and the tests replace it to make
// the journal change between the two reads without a timing race.
var readJournalEvents = ReadEvents

// VerifyCheckpoint verifies the checkpoints recorded for logPath against the
// key at keyPath and reports whether the journal still honours every one of
// them. A checkpoint covers a prefix: the chain must be intact, the journal
// must hold at least count events, the event at position count must hash to
// tip_hash, and the signature must verify. Events appended after signing do
// not invalidate it; truncating or rewriting the signed prefix does. The
// checkpoints themselves must form a gap-free chain 1..N.
//
// The Python function returns a bare bool and so does this one; the CLI
// prints a one-line verdict either way. The error is for a checkpoints file or
// journal that is there but cannot be read, or a journal that shrank between
// the two reads made of it, where Python raises: that is no verdict at all, so
// it is not reported as an invalid checkpoint either. A key that cannot be
// loaded is a plain false, as in Python.
func VerifyCheckpoint(logPath, keyPath string) (bool, error) {
	checkpoints, err := ReadCheckpoints(logPath)
	if err != nil {
		return false, err
	}
	if len(checkpoints) == 0 {
		return false, nil
	}
	public, err := LoadPublicKey(keyPath)
	if err != nil {
		return false, nil
	}

	// Trust file order for nothing: validate every signature first. A
	// checkpoint with no usable count attests to nothing and is ignored.
	var valid []*canonical.Value
	for _, checkpoint := range checkpoints {
		if _, ok := usableCount(checkpoint.Get("count")); !ok {
			continue
		}
		sigValue := checkpoint.Get("signature")
		if sigValue.Kind != canonical.String {
			continue
		}
		signature, err := pyBase64Decode(sigValue.Str)
		if err != nil {
			continue
		}
		payload, err := SignedPayload(checkpoint)
		if err != nil {
			continue
		}
		if !ed25519.Verify(public, payload, signature) {
			continue
		}
		valid = append(valid, checkpoint)
	}
	if len(valid) == 0 {
		return false, nil
	}

	// Sort by signed index, with anything that is not an int sorting first,
	// then require indices 1..N each naming its predecessor's hash.
	sort.SliceStable(valid, func(i, j int) bool {
		return indexSortKey(valid[i]).Cmp(indexSortKey(valid[j])) < 0
	})
	prevHash := GenesisPrevHash
	for position, checkpoint := range valid {
		if !checkpoint.Get("index").EqualsPyInt(big.NewInt(int64(position + 1))) {
			return false, nil // a checkpoint was deleted, duplicated, or reordered
		}
		if !canonical.Equal(checkpoint.Get("prev_checkpoint_hash"), canonical.NewString(prevHash)) {
			return false, nil
		}
		prevHash, err = CheckpointHash(checkpoint)
		if err != nil {
			return false, nil
		}
	}

	result, err := Verify(logPath)
	if err != nil {
		return false, err
	}
	if !result.OK {
		return false, nil
	}
	events, err := readJournalEvents(logPath)
	if err != nil {
		return false, err
	}
	if len(events) < result.Count {
		// Verify and ReadEvents each read the journal, and it shrank in
		// between: rotated, truncated, or not a regular file at all. Neither
		// read speaks for the journal, so there is no verdict to give, and the
		// count from the first must not index the events of the second.
		return false, fmt.Errorf("%s changed while it was being verified (%d events, then %d)",
			logPath, result.Count, len(events))
	}
	// Every valid checkpoint must still hold, not just the widest one.
	for _, checkpoint := range valid {
		count, _ := usableCount(checkpoint.Get("count"))
		if big.NewInt(int64(result.Count)).Cmp(count) < 0 {
			return false, nil // truncated below a signed prefix
		}
		if !canonical.Equal(events[count.Int64()-1].Get("hash"), checkpoint.Get("tip_hash")) {
			return false, nil
		}
	}
	return true, nil
}

// indexSortKey is Python's `c["index"] if isinstance(c.get("index"), int)
// else -1`. Bools count as ints there, so true sorts as 1.
func indexSortKey(checkpoint *canonical.Value) *big.Int {
	index := checkpoint.Get("index")
	if index.IsPyInt() {
		return index.PyIntValue()
	}
	return big.NewInt(-1)
}

// pyBase64Decode is base64.b64decode(s) with its default validate=False:
// characters outside the alphabet are discarded, decoding stops at the first
// complete padding, and an unpadded tail is an error. It reproduces CPython's
// binascii.a2b_base64 in non-strict mode so that a signature string Python
// accepts is accepted here and vice versa. Non-ASCII input is refused, as
// Python refuses a str with non-ASCII characters.
func pyBase64Decode(s string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return nil, errors.New("string argument should contain only ASCII characters")
		}
	}
	var out []byte
	quadPos := 0
	pads := 0
	var leftchar byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '=' {
			if quadPos >= 2 {
				pads++
				if quadPos+pads >= 4 {
					return out, nil
				}
			}
			continue
		}
		v := base64Value(c)
		if v < 0 {
			continue
		}
		pads = 0
		switch quadPos {
		case 0:
			quadPos = 1
			leftchar = byte(v)
		case 1:
			quadPos = 2
			out = append(out, leftchar<<2|byte(v)>>4)
			leftchar = byte(v) & 0x0f
		case 2:
			quadPos = 3
			out = append(out, leftchar<<4|byte(v)>>2)
			leftchar = byte(v) & 0x03
		case 3:
			quadPos = 0
			out = append(out, leftchar<<6|byte(v))
			leftchar = 0
		}
	}
	if quadPos != 0 {
		if quadPos == 1 {
			return nil, errors.New("number of data characters cannot be 1 more than a multiple of 4")
		}
		return nil, errors.New("Incorrect padding")
	}
	return out, nil
}

func base64Value(c byte) int {
	switch {
	case c >= 'A' && c <= 'Z':
		return int(c - 'A')
	case c >= 'a' && c <= 'z':
		return int(c-'a') + 26
	case c >= '0' && c <= '9':
		return int(c-'0') + 52
	case c == '+':
		return 62
	case c == '/':
		return 63
	}
	return -1
}
