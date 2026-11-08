package imapx

import (
	"context"
	"errors"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

// ErrConnClosed is returned when the server closed the connection (BYE,
// auto-logout, network drop).
var ErrConnClosed = errors.New("connection closed by server")

// IdleResult says why Idle returned without error.
type IdleResult int

const (
	IdleEvent IdleResult = iota // untagged EXISTS / EXPUNGE / FETCH arrived
	IdleRenew                   // renewal interval elapsed; the IDLE was ended cleanly
)

// Watch is a dedicated connection with one folder selected (read-only), used
// to wait for changes with IDLE or, when the server lacks IDLE, to poll with
// NOOP. Every operation is bounded by a deadline.
type Watch struct {
	c       *imapclient.Client
	events  chan struct{}
	canIdle bool
	timeout time.Duration
}

// OpenWatch dials, logs in and EXAMINEs folder. opTimeout bounds each
// individual protocol operation (connect, select, IDLE start/stop, NOOP).
func (a *Account) OpenWatch(ctx context.Context, folder string, opTimeout time.Duration) (*Watch, error) {
	if opTimeout <= 0 {
		opTimeout = 30 * time.Second
	}
	w := &Watch{events: make(chan struct{}, 1), timeout: opTimeout}
	notify := func() {
		select {
		case w.events <- struct{}{}:
		default:
		}
	}
	h := &imapclient.UnilateralDataHandler{
		Expunge: func(uint32) { notify() },
		Mailbox: func(d *imapclient.UnilateralDataMailbox) {
			if d.NumMessages != nil {
				notify()
			}
		},
		Fetch: func(*imapclient.FetchMessageData) { notify() },
	}
	dctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	cl, err := a.dialClient(dctx, h)
	if err != nil {
		return nil, err
	}
	w.c = cl
	err = w.bounded(ctx, func() error {
		w.canIdle = cl.Caps().Has(imap.CapIdle)
		_, err := examine(cl, folder)
		return err
	})
	if err != nil {
		w.Close()
		return nil, err
	}
	return w, nil
}

// CanIdle reports whether the server advertises IDLE.
func (w *Watch) CanIdle() bool { return w.canIdle }

// Events delivers a token when untagged change data arrived.
func (w *Watch) Events() <-chan struct{} { return w.events }

// Closed is closed when the connection is gone.
func (w *Watch) Closed() <-chan struct{} { return w.c.Closed() }

// Close drops the connection without blocking.
func (w *Watch) Close() { closeAsync(w.c) }

// bounded runs fn with a deadline of w.timeout (and ctx); on expiry the
// connection is closed so that a wedged library call returns.
func (w *Watch) bounded(ctx context.Context, fn func() error) error {
	tctx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()
	stop := context.AfterFunc(tctx, func() { closeAsync(w.c) })
	defer stop()
	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- errors.New("internal error in imap watch")
			}
		}()
		done <- fn()
	}()
	select {
	case err := <-done:
		if tctx.Err() != nil && err != nil {
			return tctx.Err()
		}
		return err
	case <-tctx.Done():
		return tctx.Err()
	}
}

// Noop sends NOOP (liveness probe; pending untagged data is delivered to Events).
func (w *Watch) Noop(ctx context.Context) error {
	return w.bounded(ctx, func() error { return w.c.Noop().Wait() })
}

// Idle runs one IDLE cycle: it returns IdleEvent as soon as the server reports
// a change, IdleRenew after renew elapsed (IDLE ended cleanly so the caller
// can immediately start a new one), or an error (connection dropped, server
// logout, deadline, cancellation). A change already pending is reported
// without entering IDLE.
func (w *Watch) Idle(ctx context.Context, renew time.Duration) (IdleResult, error) {
	select {
	case <-w.events:
		return IdleEvent, nil
	default:
	}
	var cmd *imapclient.IdleCommand
	if err := w.bounded(ctx, func() error {
		var err error
		cmd, err = w.c.Idle()
		return err
	}); err != nil {
		w.Close()
		return 0, err
	}
	timer := time.NewTimer(renew)
	defer timer.Stop()
	res := IdleRenew
	var werr error
	select {
	case <-w.events:
		res = IdleEvent
	case <-timer.C:
	case <-w.c.Closed():
		werr = ErrConnClosed
	case <-ctx.Done():
		werr = ctx.Err()
	}
	if werr != nil {
		w.Close()
		return 0, werr
	}
	if err := w.bounded(ctx, func() error {
		if err := cmd.Close(); err != nil {
			return err
		}
		return cmd.Wait()
	}); err != nil {
		w.Close()
		return 0, err
	}
	return res, nil
}
