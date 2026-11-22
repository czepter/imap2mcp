package imapx

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// rawServer is a minimal IMAP server that advertises ID and AUTH=PLAIN and
// refuses every login. The go-imap server does not implement ID, so this one
// records the commands it sees.
type rawServer struct {
	ln   net.Listener
	pool *x509.CertPool
	mu   sync.Mutex
	cmds []string
}

func newRawServer(t *testing.T, caps string) *rawServer {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mail.example.test"},
		DNSNames: []string{"mail.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	s := &rawServer{ln: ln, pool: pool}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c, caps)
		}
	}()
	return s
}

func (s *rawServer) serve(c net.Conn, caps string) {
	defer c.Close()
	r := bufio.NewReader(c)
	fmt.Fprintf(c, "* OK [CAPABILITY IMAP4rev1 %s] Fake greeting ready\r\n", caps)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		tag, cmd := f[0], strings.ToUpper(f[1])
		s.mu.Lock()
		s.cmds = append(s.cmds, cmd)
		s.mu.Unlock()
		switch cmd {
		case "ID":
			fmt.Fprintf(c, "* ID (\"name\" \"FakeSrv\" \"vendor\" \"Fake Inc\" \"version\" \"9.1\")\r\n%s OK ID done\r\n", tag)
		case "AUTHENTICATE":
			fmt.Fprintf(c, "+ \r\n")
			_, _ = r.ReadString('\n')
			fmt.Fprintf(c, "%s NO [AUTHENTICATIONFAILED] Login denied for fake reasons\r\n", tag)
		case "LOGIN":
			fmt.Fprintf(c, "%s NO [AUTHENTICATIONFAILED] Login denied for fake reasons\r\n", tag)
		default:
			fmt.Fprintf(c, "%s BAD unsupported\r\n", tag)
		}
	}
}

func (s *rawServer) commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.cmds...)
}

func dialRaw(t *testing.T, s *rawServer, sendID bool) (string, error) {
	t.Helper()
	host, portS, _ := net.SplitHostPort(s.ln.Addr().String())
	var port int
	fmt.Sscan(portS, &port)
	cr := Creds{Host: "mail.example.test", IP: host, Port: port, User: "alice@example.test", Pass: "s3cret-pass"}
	a := NewAccount(cr, func(sn string) *tls.Config { return &tls.Config{RootCAs: s.pool, ServerName: sn} })
	var mu sync.Mutex
	var lines []string
	a.SetLogf(func(f string, args ...any) { mu.Lock(); lines = append(lines, fmt.Sprintf(f, args...)); mu.Unlock() })
	a.SetSendID(sendID)
	err := a.Verify(context.Background())
	mu.Lock()
	defer mu.Unlock()
	return strings.Join(lines, "\n"), err
}

func TestIDSentBeforeAuthenticateAndLoggedOnRefusal(t *testing.T) {
	s := newRawServer(t, "ID AUTH=PLAIN")
	out, err := dialRaw(t, s, true)
	if err == nil {
		t.Fatal("expected refusal")
	}
	cmds := s.commands()
	if len(cmds) < 2 || cmds[0] != "ID" || cmds[1] != "AUTHENTICATE" {
		t.Fatalf("command order %v", cmds)
	}
	for _, want := range []string{
		`method="AUTHENTICATE PLAIN"`, `code="AUTHENTICATIONFAILED"`, `text="Login denied for fake reasons"`, "id_sent=true",
		`server_id="name=FakeSrv vendor=Fake Inc version=9.1"`, "sni=mail.example.test", "remote=127.0.0.1:", "tls=TLS 1.3", "cipher=TLS_",
		"Fake greeting ready", "strike=1/3",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("log lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "s3cret-pass") || strings.Contains(out, "alice") {
		t.Fatalf("log leaks credentials:\n%s", out)
	}
	t.Log(out)
}

func TestIDNotSentWhenDisabledOrNotAdvertised(t *testing.T) {
	s := newRawServer(t, "ID AUTH=PLAIN")
	out, _ := dialRaw(t, s, false)
	if c := s.commands(); len(c) != 1 || c[0] != "AUTHENTICATE" || !strings.Contains(out, "id_sent=false") {
		t.Fatalf("disabled: %v\n%s", c, out)
	}
	s2 := newRawServer(t, "AUTH=PLAIN")
	_, _ = dialRaw(t, s2, true)
	if c := s2.commands(); len(c) != 1 || c[0] != "AUTHENTICATE" {
		t.Fatalf("not advertised: %v", c)
	}
}
