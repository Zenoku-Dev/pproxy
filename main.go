// pproxy — один порт для SOCKS5 и HTTP CONNECT: телефон как выход в интернет.
// Клиент использует обычное устройство в обычной сети, с настоящим TLS-отпечатком —
// антибот CF видит обычный телефон, а не терминатор-машину из машин/долины.
//
// Авторизация: PPROXY_USER/PPROXY_PASS (Basic для HTTP CONNECT, RFC 1929 для SOCKS5).
// Без них — NOAUTH/без пароля (ставьте только на loopback, только для личного доступа).
// Только TCP CONNECT; лимит одновременных соединений PPROXY_MAXCONN (по умолчанию 64).
package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	listenAddr = getenv("PPROXY_LISTEN", "0.0.0.0:8778")
	user       = os.Getenv("PPROXY_USER")
	pass       = os.Getenv("PPROXY_PASS")
	maxConn    = atoi(os.Getenv("PPROXY_MAXCONN"), 64)

	dialer = &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}

	// DNS напрямую через UDP, минуя netd (NODATA для getaddrinfo на Termux)
	resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 5 * time.Second}
			c, err := d.DialContext(ctx, "udp", "1.1.1.1:53")
			if err != nil {
				c, err = d.DialContext(ctx, "udp", "8.8.8.8:53")
			}
			return c, err
		},
	}
)

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func atoi(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil && n > 0 {
		return n
	}
	return def
}

func needAuth() bool { return user != "" || pass != "" }

func authOK(u, p string) bool {
	return subtle.ConstantTimeCompare([]byte(u), []byte(user)) == 1 &&
		subtle.ConstantTimeCompare([]byte(p), []byte(pass)) == 1
}

type target struct{ host, port string }

func (t target) String() string { return net.JoinHostPort(t.host, t.port) }

func resolve(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	return resolver.LookupIP(ctx, "ip", host)
}

func dialTarget(ctx context.Context, t target) (net.Conn, error) {
	ips, err := resolve(ctx, t.host)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, ip := range ips {
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), t.port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func pipeBidirectional(c1, c2 net.Conn) {
	_ = c1.SetDeadline(time.Time{})
	_ = c2.SetDeadline(time.Time{})
	var wg sync.WaitGroup
	wg.Add(2)
	half := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		if tc, ok := dst.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	go half(c2, c1)
	go half(c1, c2)
	wg.Wait()
}

// ---------- SOCKS5 ----------

func handleSOCKS(ctx context.Context, c net.Conn, br *bufio.Reader, clientIP string) error {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return err
	}
	if hdr[0] != 0x05 {
		return errors.New("не SOCKS5")
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return err
	}
	if needAuth() {
		c.Write([]byte{0x05, 0x02}) // username/password
		found := false
		for _, m := range methods {
			if m == 0x02 {
				found = true
				break
			}
		}
		if !found {
			c.Write([]byte{0x05, 0xff})
			return errors.New("socks: клиент не предложил логин/пароль")
		}
		auth := make([]byte, 2)
		if _, err := io.ReadFull(br, auth); err != nil {
			return err
		}
		if auth[0] != 0x01 {
			return errors.New("socks: неизвестная под-версия auth")
		}
		ub := make([]byte, int(auth[1]))
		if _, err := io.ReadFull(br, ub); err != nil {
			return err
		}
		pLen := make([]byte, 1)
		if _, err := io.ReadFull(br, pLen); err != nil {
			return err
		}
		pb := make([]byte, int(pLen[0]))
		if _, err := io.ReadFull(br, pb); err != nil {
			return err
		}
		if !authOK(string(ub), string(pb)) {
			c.Write([]byte{0x01, 0x01})
			return errors.New("socks: отказ: неверные учётные данные")
		}
		c.Write([]byte{0x01, 0x00})
	} else {
		haveNoAuth := false
		for _, m := range methods {
			if m == 0x00 {
				haveNoAuth = true
				break
			}
		}
		if !haveNoAuth {
			c.Write([]byte{0x05, 0xff})
			return errors.New("socks: NOAUTH не предложен клиентом")
		}
		c.Write([]byte{0x05, 0x00})
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil {
		return err
	}
	if req[0] != 0x05 || req[1] != 0x01 { // только CONNECT
		c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return errors.New("socks: только CONNECT")
	}
	var host string
	switch req[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return err
		}
		host = net.IP(b).String()
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(br, l); err != nil {
			return err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(br, b); err != nil {
			return err
		}
		host = string(b)
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return err
		}
		host = net.IP(b).String()
	default:
		c.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return errors.New("socks: неизвестный ATYP")
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return err
	}
	t := target{host, strconv.Itoa(int(binary.BigEndian.Uint16(pb)))}
	log.Printf("socks5 %s src=%s", t, clientIP)
	up, err := dialTarget(ctx, t)
	if err != nil {
		c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return err
	}
	// BND.ADDR: обязаны вернуть что-то корректное — отдаём нули (найлегитимно и не раскрывает адреса)
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		up.Close()
		return err
	}
	pipeBidirectional(c, up)
	up.Close()
	return nil
}

// ---------- HTTP CONNECT ----------

func handleHTTPCONNECT(ctx context.Context, c net.Conn, br *bufio.Reader, clientIP string) error {
	line, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	fields := strings.Fields(line)
	if len(fields) < 3 || !strings.EqualFold(fields[0], "CONNECT") {
		io.WriteString(c, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
		return errors.New("только CONNECT")
	}
	host, port, err := net.SplitHostPort(fields[1])
	if err != nil {
		io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
		return fmt.Errorf("CONNECT %q: %w", fields[1], err)
	}
	headers := map[string]string{}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, ":")
		if ok {
			headers[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	if needAuth() {
		ok := false
		if a := headers["proxy-authorization"]; strings.HasPrefix(a, "Basic ") {
			if dec, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(a, "Basic ")); err == nil {
				if u, p, found := strings.Cut(string(dec), ":"); found && authOK(u, p) {
					ok = true
				}
			}
		}
		if !ok {
			io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"pproxy\"\r\nContent-Length: 0\r\n\r\n")
			return errors.New("http: отказ: неверные учётные данные")
		}
	}
	t := target{host, port}
	log.Printf("http CONNECT %s src=%s", t, clientIP)
	up, err := dialTarget(ctx, t)
	if err != nil {
		io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return err
	}
	io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	pipeBidirectional(c, up)
	up.Close()
	return nil
}

// ---------- сервер ----------

func handle(c net.Conn, sem chan struct{}) {
	defer func() { <-sem; c.Close() }()
	clientIP := ""
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		clientIP = a.IP.String()
	}
	br := bufio.NewReaderSize(c, 8192)
	first, err := br.Peek(1)
	if err != nil {
		log.Printf("сброс от %s: %v", clientIP, err)
		return
	}
	var herr error
	if first[0] == 0x05 {
		herr = handleSOCKS(context.Background(), c, br, clientIP)
	} else {
		herr = handleHTTPCONNECT(context.Background(), c, br, clientIP)
	}
	if herr != nil && herr != io.EOF {
		log.Printf("%s: %v", clientIP, herr)
	}
}

func main() {
	sem := make(chan struct{}, maxConn)
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("listen %s: %v", listenAddr, err)
	}
	if needAuth() {
		log.Printf("pproxy listen %s (auth включена, maxconn %d)", listenAddr, maxConn)
	} else {
		log.Printf("pproxy listen %s (auth ВЫКЛЮЧЕНА — только для loopback!, maxconn %d)", listenAddr, maxConn)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			log.Printf("переполнение (%d), отклоняю %s", maxConn, c.RemoteAddr())
			c.Close()
			continue
		}
		go handle(c, sem)
	}
}
