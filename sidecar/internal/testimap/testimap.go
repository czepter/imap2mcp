// Package testimap starts an in-memory IMAPS server (go-imap imapmemserver)
// with a throw-away CA, for tests and benchmarks only.
package testimap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
)

const (
	User       = "alice@example.test"
	Pass       = "s3cret-Pa55w0rd!xyz"
	ServerName = "mail.example.test"
)

// Server is a running test IMAPS server.
type Server struct {
	Addr   string // 127.0.0.1:port
	IP     string
	Port   int
	CAFile string
	CAPool *x509.CertPool
	User   *imapmemserver.User
	srv    *imapserver.Server
}

type lit struct {
	b []byte
	o int
}

func (l *lit) Read(p []byte) (int, error) {
	if l.o >= len(l.b) {
		return 0, io.EOF
	}
	n := copy(p, l.b[l.o:])
	l.o += n
	return n, nil
}
func (l *lit) Size() int64 { return int64(len(l.b)) }

// New starts a server with the given folders created.
func New(t testing.TB, folders ...string) *Server {
	t.Helper()
	dir := t.TempDir()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: ServerName},
		DNSNames: []string{ServerName}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}

	mem := imapmemserver.New()
	user := imapmemserver.NewUser(User, Pass)
	user.Create("INBOX", nil)
	for _, f := range folders {
		user.Create(f, nil)
	}
	mem.AddUser(user)
	srv := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return mem.NewSession(), nil, nil
		},
		TLSConfig:    &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}},
		InsecureAuth: true,
	})
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srv2cfg(leafDER, leafKey))
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { _ = srv.Close() })
	a := ln.Addr().(*net.TCPAddr)
	return &Server{Addr: a.String(), IP: "127.0.0.1", Port: a.Port, CAFile: caFile, CAPool: pool, User: user, srv: srv}
}

func srv2cfg(der []byte, key *ecdsa.PrivateKey) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

// Msg builds an RFC 5322 message.
func Msg(i int, subject, from, to string, size int) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\nTo: %s\r\nSubject: %s\r\nMessage-ID: <m%d@example.test>\r\n", from, to, subject, i)
	fmt.Fprintf(&b, "Date: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n",
		time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(i)*time.Minute).Format(time.RFC1123Z))
	fmt.Fprintf(&b, "body of message %d\r\n", i)
	for b.Len() < size {
		b.WriteString("lorem ipsum dolor sit amet\r\n")
	}
	return []byte(b.String())
}

// Append adds a message in-process (fast) and returns its UID.
func (s *Server) Append(folder string, raw []byte, flags ...imap.Flag) imap.UID {
	d, err := s.User.Append(folder, &lit{b: raw}, &imap.AppendOptions{Flags: flags, Time: time.Now()})
	if err != nil {
		panic(err)
	}
	return d.UID
}

// Client returns a logged-in test client (for external mutations).
func (s *Server) Client(t testing.TB) *imapclient.Client {
	t.Helper()
	c, err := imapclient.DialTLS(s.Addr, &imapclient.Options{TLSConfig: &tls.Config{RootCAs: s.CAPool, ServerName: ServerName}})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Login(User, Pass).Wait(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// SetFlags replaces flags of a UID.
func (s *Server) SetFlags(t testing.TB, folder string, uid imap.UID, flags ...imap.Flag) {
	t.Helper()
	c := s.Client(t)
	if _, err := c.Select(folder, nil).Wait(); err != nil {
		t.Fatal(err)
	}
	if err := c.Store(imap.UIDSetNum(uid), &imap.StoreFlags{Op: imap.StoreFlagsSet, Silent: true, Flags: flags}, nil).Close(); err != nil {
		t.Fatal(err)
	}
}

// Expunge removes UIDs (external expunge).
func (s *Server) Expunge(t testing.TB, folder string, uids ...imap.UID) {
	t.Helper()
	c := s.Client(t)
	if _, err := c.Select(folder, nil).Wait(); err != nil {
		t.Fatal(err)
	}
	set := imap.UIDSetNum(uids...)
	if err := c.Store(set, &imap.StoreFlags{Op: imap.StoreFlagsAdd, Silent: true, Flags: []imap.Flag{imap.FlagDeleted}}, nil).Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.UIDExpunge(set).Close(); err != nil {
		t.Fatal(err)
	}
}

// ResetFolder deletes and recreates a folder: the server assigns a new UIDVALIDITY.
func (s *Server) ResetFolder(folder string) {
	_ = s.User.Delete(folder)
	_ = s.User.Create(folder, nil)
}
