// Package engine holds the header cache, the sync state machine and the
// search logic. It never stores message bodies.
package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

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

func errAuthFailed() *Error      { return errf(CodeUpstream, "upstream authentication failed") }
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
		return errAuthFailed()
	}
	if isTimeout(err) {
		return errf(CodeTimeout, "upstream request timed out")
	}
	if isProtocol(err) {
		return errf(CodeUpstream, "PROTOCOL_ERROR: malformed reply from the mail server")
	}
	return errf(CodeUpstream, "upstream error: %s", cr.Redact(err.Error()))
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// isProtocol recognises parse failures of the IMAP client library (malformed or
// unexpected server data). The connection is already closed when they occur.
func isProtocol(err error) bool {
	m := err.Error()
	for _, p := range []string{"in response", "in continue-req", "imapwire:", "unmatched continuation", "unknown tag", "panic reading response", "got error before greeting"} {
		if strings.Contains(m, p) {
			return true
		}
	}
	return false
}

// ErrorCode maps an error to the stable code string used by the status RPC
// and by the Node error taxonomy.
func ErrorCode(err error) string {
	var ee *Error
	switch {
	case err == nil:
		return ""
	case errors.Is(err, imapx.ErrAuth):
		return "AUTH_FAILED"
	case errors.Is(err, context.DeadlineExceeded) || isTimeout(err):
		return "TIMEOUT"
	case isProtocol(err):
		return "PROTOCOL_ERROR"
	case errors.As(err, &ee) && ee.Code == CodeTimeout:
		return "TIMEOUT"
	}
	return "UPSTREAM_ERROR"
}
