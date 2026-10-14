package aileron

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aileron-sh/aileron/verifiers/go/canonical"
)

const usage = `usage: aileron-verify <command> [options]

commands:
  verify <log> [--skip-checkpoint-check]
      Verify a hash-chained journal. Exit 0 when intact, 2 when tampered.
      An adjacent <log>.checkpoints.jsonl is cross-checked (unauthenticated)
      unless --skip-checkpoint-check is given.
  verify-checkpoint <log> [--key <public key PEM>]
      Verify the signed checkpoints for a journal. Exit 0 when every
      checkpoint holds, 1 otherwise.
  canonical [file]
      Read one JSON document (from file or stdin) and print its canonical
      form, the exact bytes Aileron hashes. A debugging aid.
`

// Run executes the command line in args (without the program name), writing
// to stdout and stderr, and returns the process exit code. It follows the
// Python CLI: verify exits 2 on tamper, verify-checkpoint exits 1 on an
// invalid checkpoint, and 1 is used for operational errors.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(stderr, usage)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	switch args[0] {
	case "verify":
		return cmdVerify(args[1:], stdout, stderr)
	case "verify-checkpoint":
		return cmdVerifyCheckpoint(args[1:], stdout, stderr)
	case "canonical":
		return cmdCanonical(args[1:], stdout, stderr)
	}
	fmt.Fprintf(stderr, "error: unknown command %q\n%s", args[0], usage)
	return 2
}

// parseArgs splits args into positionals and the options the two commands
// share. Options may appear anywhere, as with argparse.
func parseArgs(args []string, stderr io.Writer) (positional []string, key string, skip bool, ok bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--skip-checkpoint-check":
			skip = true
		case a == "--key":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "error: --key requires a value")
				return nil, "", false, false
			}
			i++
			key = args[i]
		case strings.HasPrefix(a, "--key="):
			key = strings.TrimPrefix(a, "--key=")
		case a == "-h" || a == "--help":
			fmt.Fprint(stderr, usage)
			return nil, "", false, false
		case strings.HasPrefix(a, "-") && a != "-":
			fmt.Fprintf(stderr, "error: unknown option %s\n", a)
			return nil, "", false, false
		default:
			positional = append(positional, a)
		}
	}
	return positional, key, skip, true
}

func cmdVerify(args []string, stdout, stderr io.Writer) int {
	positional, _, skip, ok := parseArgs(args, stderr)
	if !ok {
		return 2
	}
	if len(positional) != 1 {
		fmt.Fprintf(stderr, "error: verify takes exactly one log path\n%s", usage)
		return 2
	}
	logPath := positional[0]
	if info, err := os.Stat(logPath); err == nil && info.IsDir() {
		fmt.Fprintf(stderr, "error: %s is a directory\n", logPath)
		return 1
	}

	result := Verify(logPath)
	if !result.OK {
		for _, e := range result.Errors {
			fmt.Fprintf(stderr, "error: %s\n", e)
		}
		seq := "None"
		if result.FirstBadSeq != nil {
			seq = result.FirstBadSeq.String()
		}
		fmt.Fprintf(stderr, "TAMPERED at seq %s in %s\n", seq, logPath)
		return 2
	}

	// An intact chain is not the whole story: truncating the tail leaves a
	// perfectly valid shorter chain. If a checkpoint next to the log says
	// more events existed, that is evidence of tampering and must not be
	// reported as OK.
	if !skip {
		problems, err := CheckAgainstCheckpoints(logPath)
		if err != nil {
			fmt.Fprintf(stderr, "error: %s\n", err)
			return 1
		}
		if len(problems) > 0 {
			for _, p := range problems {
				fmt.Fprintf(stderr, "error: %s\n", p)
			}
			fmt.Fprintf(stderr, "TAMPERED: chain is internally valid but contradicts %s\n", CheckpointsPath(logPath))
			fmt.Fprintln(stderr, "note: signatures were not checked here - run "+
				"'aileron verify-checkpoint' with the public key you trust.")
			return 2
		}
	}

	fmt.Fprintf(stdout, "OK: %d events verified in %s\n", result.Count, logPath)
	return 0
}

// defaultVerifyKey resolves the key to verify with when --key is absent:
// the public key next to the log, then the private key next to it, then the
// same two names in the working directory, else the public key name.
func defaultVerifyKey(logPath, key string) string {
	if key != "" {
		return key
	}
	parent := filepath.Dir(logPath)
	for _, candidate := range []string{
		filepath.Join(parent, PublicKeyName), filepath.Join(parent, PrivateKeyName),
		PublicKeyName, PrivateKeyName,
	} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return PublicKeyName
}

func cmdVerifyCheckpoint(args []string, stdout, stderr io.Writer) int {
	positional, keyArg, _, ok := parseArgs(args, stderr)
	if !ok {
		return 2
	}
	if len(positional) != 1 {
		fmt.Fprintf(stderr, "error: verify-checkpoint takes exactly one log path\n%s", usage)
		return 2
	}
	logPath := positional[0]
	key := defaultVerifyKey(logPath, keyArg)
	if _, err := os.Stat(key); err != nil {
		fmt.Fprintf(stderr, "error: no verification key found (looked for %s). "+
			"Pass --key with the public key you trust.\n", key)
		return 1
	}

	// The key IS the trust anchor. Say exactly which file was used, and warn
	// when it came from alongside the evidence rather than from the operator.
	resolved := resolvePath(key)
	keyBytes, err := os.ReadFile(resolved)
	if err != nil {
		fmt.Fprintf(stderr, "error: %s\n", err)
		return 1
	}
	sum := sha256.Sum256(keyBytes)
	fmt.Fprintf(stdout, "verifying against key %s (sha256:%s)\n", resolved, hex.EncodeToString(sum[:8]))
	if keyArg == "" && filepath.Dir(resolved) == filepath.Dir(resolvePath(logPath)) {
		fmt.Fprintln(stderr, "warning: this key sits next to the log it attests. An attacker "+
			"with write access to that directory could have replaced both. "+
			"Pass --key with an out-of-band copy for a meaningful check.")
	}

	valid, err := VerifyCheckpoint(logPath, key)
	if err != nil {
		fmt.Fprintf(stderr, "error: %s\n", err)
		return 1
	}
	if valid {
		fmt.Fprintf(stdout, "OK: checkpoint valid for %s\n", logPath)
		return 0
	}
	fmt.Fprintf(stderr, "FAILED: checkpoint invalid for %s\n", logPath)
	return 1
}

// resolvePath is Python's Path.resolve(): absolute, symlinks followed where
// possible.
func resolvePath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		return real
	}
	return abs
}

func cmdCanonical(args []string, stdout, stderr io.Writer) int {
	var data []byte
	var err error
	switch len(args) {
	case 0:
		data, err = io.ReadAll(os.Stdin)
	case 1:
		data, err = os.ReadFile(args[0])
	default:
		fmt.Fprintf(stderr, "error: canonical takes at most one file\n%s", usage)
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: %s\n", err)
		return 1
	}
	value, err := canonical.Parse(canonical.Strip(string(data)))
	if err != nil {
		fmt.Fprintf(stderr, "error: invalid JSON: %s\n", err)
		return 1
	}
	out, err := canonical.Marshal(value)
	if err != nil {
		fmt.Fprintf(stderr, "error: %s\n", err)
		return 1
	}
	stdout.Write(out)
	fmt.Fprintln(stdout)
	return 0
}
