// Interop peer built on quic-go/webtransport-go v0.13, which hard-requires
// the RESET_STREAM_AT transport extension - only the pure-OCaml backend
// negotiates it (quiche cannot; see cloudflare/quiche#2564).
//
//	go run . -mode client -url https://127.0.0.1:4433/echo
//	    connects to an echo server, checks bidi/uni/datagram echo,
//	    prints GO-CLIENT-OK and exits 0 on success.
//
//	go run . -mode server
//	    starts an echo server on 127.0.0.1 (random port), prints PORT=N.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
)

func runClient(url string) error {
	d := webtransport.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3"},
		},
		QUICConfig: &quic.Config{EnableDatagrams: true, EnableStreamResetPartialDelivery: true},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, sess, err := d.Dial(ctx, url, nil)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	// Bidi echo on the same stream.
	str, err := sess.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open bidi: %w", err)
	}
	msg := []byte("go-bidi-ping")
	if _, err := str.Write(msg); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if err := str.Close(); err != nil {
		return fmt.Errorf("close write: %w", err)
	}
	echoed, err := io.ReadAll(str)
	if err != nil {
		return fmt.Errorf("read echo: %w", err)
	}
	if !bytes.Equal(echoed, msg) {
		return fmt.Errorf("bad bidi echo: %q", echoed)
	}
	// Uni out; echo comes back on a server-initiated uni.
	us, err := sess.OpenUniStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open uni: %w", err)
	}
	if _, err := us.Write([]byte("go-uni-ping")); err != nil {
		return fmt.Errorf("uni write: %w", err)
	}
	if err := us.Close(); err != nil {
		return fmt.Errorf("uni close: %w", err)
	}
	ru, err := sess.AcceptUniStream(ctx)
	if err != nil {
		return fmt.Errorf("accept uni: %w", err)
	}
	uniEcho, err := io.ReadAll(ru)
	if err != nil {
		return fmt.Errorf("uni read: %w", err)
	}
	if !bytes.Equal(uniEcho, []byte("go-uni-ping")) {
		return fmt.Errorf("bad uni echo: %q", uniEcho)
	}
	// Datagram echo (unreliable: send with retry until one comes back).
	dgCtx, dgCancel := context.WithTimeout(ctx, 5*time.Second)
	defer dgCancel()
	got := make(chan []byte, 1)
	go func() {
		if d, err := sess.ReceiveDatagram(dgCtx); err == nil {
			got <- d
		}
	}()
	payload := []byte("go-dgram-ping")
sendLoop:
	for i := 0; i < 20; i++ {
		if err := sess.SendDatagram(payload); err != nil {
			return fmt.Errorf("send datagram: %w", err)
		}
		select {
		case d := <-got:
			if !bytes.Equal(d, payload) {
				return fmt.Errorf("bad datagram echo: %q", d)
			}
			break sendLoop
		case <-time.After(250 * time.Millisecond):
		}
		if i == 19 {
			return fmt.Errorf("datagram echo timed out")
		}
	}
	if err := sess.CloseWithError(0, "bye"); err != nil {
		return fmt.Errorf("close: %w", err)
	}
	fmt.Println("GO-CLIENT-OK")
	return nil
}

func selfSignedTLS() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "wtinterop"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}, nil
}

func echoSession(sess *webtransport.Session) {
	go func() {
		for {
			d, err := sess.ReceiveDatagram(context.Background())
			if err != nil {
				return
			}
			_ = sess.SendDatagram(d)
		}
	}()
	go func() {
		for {
			ru, err := sess.AcceptUniStream(context.Background())
			if err != nil {
				return
			}
			go func() {
				data, err := io.ReadAll(ru)
				if err != nil {
					return
				}
				out, err := sess.OpenUniStream()
				if err != nil {
					return
				}
				_, _ = out.Write(data)
				_ = out.Close()
			}()
		}
	}()
	for {
		str, err := sess.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go func() {
			data, err := io.ReadAll(str)
			if err != nil {
				return
			}
			_, _ = str.Write(data)
			_ = str.Close()
		}()
	}
}

func runServer() error {
	tlsConf, err := selfSignedTLS()
	if err != nil {
		return err
	}
	tlsConf = http3.ConfigureTLSConfig(tlsConf)
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return err
	}
	fmt.Printf("PORT=%d\n", udpConn.LocalAddr().(*net.UDPAddr).Port)
	mux := http.NewServeMux()
	s := webtransport.Server{
		H3: &http3.Server{
			TLSConfig:       tlsConf,
			EnableDatagrams: true,
			QUICConfig:      &quic.Config{EnableDatagrams: true, EnableStreamResetPartialDelivery: true},
			Handler:         mux,
		},
	}
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		sess, err := s.Upgrade(w, r)
		if err != nil {
			log.Printf("upgrade failed: %v", err)
			w.WriteHeader(500)
			return
		}
		go echoSession(sess)
	})
	return s.Serve(udpConn)
}

func main() {
	mode := flag.String("mode", "client", "client or server")
	url := flag.String("url", "https://127.0.0.1:4433/echo", "server URL (client mode)")
	flag.Parse()
	var err error
	switch *mode {
	case "client":
		err = runClient(*url)
	case "server":
		err = runServer()
	default:
		err = fmt.Errorf("unknown mode %q", *mode)
	}
	if err != nil {
		log.Fatal(err)
	}
}
