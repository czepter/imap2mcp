// Command sidecar is the read-only IMAP sidecar: a header cache and sync engine
// behind an authenticated Unix domain socket. See docs/DESIGN_V1.md.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/imap2mcp/sidecar/internal/engine"
	"github.com/imap2mcp/sidecar/internal/rpc"
)

func envSecs(name string, def time.Duration) time.Duration {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return def
}

func main() {
	socket := flag.String("socket", "", "unix socket path (default $SIDECAR_SOCKET or $DATA_DIR/sidecar.sock)")
	flag.Parse()
	logger := log.New(os.Stderr, "sidecar: ", log.LstdFlags)

	path := *socket
	if path == "" {
		path = os.Getenv("SIDECAR_SOCKET")
	}
	if path == "" {
		dd := os.Getenv("DATA_DIR")
		if dd == "" {
			dd = "data"
		}
		path = filepath.Join(dd, "sidecar.sock")
	}

	// The auth secret arrives on stdin (one line), never via argv or env.
	stdin := bufio.NewReader(os.Stdin)
	line, err := stdin.ReadString('\n')
	secret := strings.TrimRight(line, "\r\n")
	if (err != nil && secret == "") || len(secret) < 16 {
		logger.Fatal("expected an auth secret (>= 16 chars) as the first line on stdin")
	}

	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if f := os.Getenv("SIDECAR_EXTRA_CA_FILE"); f != "" {
		pem, err := os.ReadFile(f)
		if err != nil {
			logger.Fatalf("cannot read SIDECAR_EXTRA_CA_FILE: %v", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			logger.Fatal("SIDECAR_EXTRA_CA_FILE contains no certificates")
		}
	}
	eng := engine.New(engine.Options{
		TLS: func(sn string) *tls.Config {
			return &tls.Config{RootCAs: pool, ServerName: sn, MinVersion: tls.VersionTLS12}
		},
		ReconcileEvery: envSecs("SYNC_RECONCILE_SECS", 30*time.Second),
		AutoSyncEvery:  envSecs("SIDECAR_AUTOSYNC_SECS", 5*time.Second),
		FolderIdle:     envSecs("SIDECAR_FOLDER_IDLE_SECS", time.Hour),
		Logf:           logger.Printf,
	})
	srv, err := rpc.New(rpc.Config{Socket: path, Secret: secret, Logf: logger.Printf}, eng)
	if err != nil {
		logger.Fatal(err)
	}
	if err := srv.Listen(); err != nil {
		logger.Fatalf("listen: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go eng.RunReconciler(ctx)
	// The supervisor keeps stdin open; EOF means the parent died => exit
	// (disable with SIDECAR_KEEP_ON_STDIN_EOF=1 for manual runs).
	if os.Getenv("SIDECAR_KEEP_ON_STDIN_EOF") == "" {
		go func() {
			_, _ = io.Copy(io.Discard, stdin)
			logger.Print("stdin closed; shutting down")
			stop()
		}()
	}
	go func() {
		<-ctx.Done()
		srv.Close()
		eng.Shutdown()
	}()
	fmt.Fprintln(os.Stderr, "sidecar: listening on", path)
	if err := srv.Serve(); err != nil {
		logger.Fatalf("serve: %v", err)
	}
}
