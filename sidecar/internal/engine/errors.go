// Package engine holds the header cache, the sync state machine and the
// search logic. It never stores message bodies.
package engine

import (
	"context"
	"errors"
	"fmt"

	"github.com/imap2mcp/sidecar/internal/imapx"
)

// JSON-RPC error codes from docs/DESIGN_V1.md.
const (
	CodeAuth           = -32001
	CodeUnknownMailbox = -32002
	CodeStaleRef       = -32010
	CodeUpstream       = -32020
	CodeTimeout        = -32030
	CodeInvalidParams  = -32602
)

// Error is a coded error whose message is already free of credentials.
type Error struct {
	Code int
	Msg  string
}

func (e *Error) Error() string { return e.Msg }

func errf(code int, format string, a ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, a...)}
}

func errUnknownMailbox() *Error  { return errf(CodeUnknownMailbox, "unknown mailbox") }
func errStale(msg string) *Error { return errf(CodeStaleRef, "STALE_REFERENCE: %s", msg) }

// upstream converts an arbitrary upstream error into a redacted *Error.
func upstream(cr imapx.Creds, err error) error {
	if err == nil {
		return nil
	}
	var ee *Error
	if errors.As(err, &ee) {
		return ee
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errf(CodeTimeout, "upstream request timed out")
	}
	if errors.Is(err, context.Canceled) {
		return errf(CodeUpstream, "request cancelled")
	}
	if errors.Is(err, imapx.ErrAuth) {
		return errf(CodeUpstream, "upstream authentication failed")
	}
	return errf(CodeUpstream, "upstream error: %s", cr.Redact(err.Error()))
}
