// Command aileron-verify is an independent verifier for Aileron journals.
//
//	aileron-verify verify <log.jsonl>
//	aileron-verify verify-checkpoint <log.jsonl> --key <public key PEM>
//
// It has no dependencies outside the Go standard library and makes no
// network calls. Exit codes follow the Python CLI: verify returns 2 when the
// journal is tampered, verify-checkpoint returns 1 when a checkpoint does not
// hold, and 1 is used for operational errors.
package main

import (
	"os"

	aileron "github.com/aileron-sh/aileron/verifiers/go"
)

func main() {
	os.Exit(aileron.Run(os.Args[1:], os.Stdout, os.Stderr))
}
