package imapx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

type relayCfg struct{ path, secret, mailboxID string }

const (
	relayTimeout   = 30 * time.Second
	relayMaxReply  = 256
	relayErrPrefix = "tls relay: "
)

// dialRelay connects to the Node TLS relay, announces the mailbox and waits for
// "OK". The returned connection carries the plaintext IMAP stream; closing it
// closes the relay's upstream TLS socket. A refusal is a plain (non-auth) error.
func dialRelay(ctx context.Context, rl *relayCfg) (net.Conn, error) {
	d := net.Dialer{Timeout: relayTimeout}
	c, err := d.DialContext(ctx, "unix", rl.path)
	if err != nil {
		return nil, fmt.Errorf(relayErrPrefix+"dial: %w", err)
	}
	_ = c.SetDeadline(time.Now().Add(relayTimeout))
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	hello, _ := json.Marshal(struct {
		Auth      string `json:"auth"`
		MailboxID string `json:"mailboxId"`
	}{rl.secret, rl.mailboxID})
	if _, err := c.Write(append(hello, '\n')); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf(relayErrPrefix+"write: %w", err)
	}
	// Read the reply byte by byte so no IMAP data is consumed into a buffer.
	var line []byte
	one := make([]byte, 1)
	for {
		if _, err := c.Read(one); err != nil {
			_ = c.Close()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf(relayErrPrefix+"read: %w", err)
		}
		if one[0] == '\n' {
			break
		}
		if len(line) >= relayMaxReply {
			_ = c.Close()
			return nil, errors.New(relayErrPrefix + "reply too long")
		}
		line = append(line, one[0])
	}
	reply := strings.TrimRight(string(line), "\r")
	if reply != "OK" {
		_ = c.Close()
		return nil, errors.New(relayErrPrefix + strings.TrimPrefix(reply, "ERR "))
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

