package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net"
	"syscall"

	"github.com/fatih/pool"
)

var errUnexpectedRead = errors.New("unexpected read from socket")

type Sender struct {
	ca         string
	crt        string
	key        string
	serverName string
	insecure   bool
	remoteAddr string
	tlsConfig  *tls.Config
	connPool   pool.Pool
}

func (s *Sender) Start(sendCh chan []byte) {
	certPool, pair, err := createCertPool(s.ca, s.crt, s.key)
	if err != nil {
		log.Fatalln(err)
	}

	c := &tls.Config{
		RootCAs:      certPool,
		Certificates: []tls.Certificate{*pair},
	}
	if s.insecure {
		c.InsecureSkipVerify = true
	}
	if s.serverName != "" {
		c.ServerName = s.serverName
	}
	s.tlsConfig = c
	err = s.newPool()
	if err != nil {
		log.Fatalln(err)
	}
	s.send(sendCh)
}

func (s *Sender) newPool() error {
	factory := func() (net.Conn, error) {
		c, err := tls.DialWithDialer(&net.Dialer{}, "tcp", s.remoteAddr, s.tlsConfig)
		if err != nil {
			return nil, err
		}
		return c, nil
	}
	p, err := pool.NewChannelPool(5, 30, factory)
	s.connPool = p
	return err
}

func (s *Sender) send(sendCh chan []byte) {
	for m := range sendCh {
		var conn net.Conn
		var err error
		for {
			conn, err = s.connPool.Get()
			if err != nil {
				log.Println(err)
				continue
			}
			err = connCheck(conn)
			if err != nil {
				log.Println(err)
				continue
			}
			break
		}
		conn.Write(m)
		conn.Close()
	}
}

func createCertPool(ca, crt, pem string) (*x509.CertPool, *tls.Certificate, error) {
	buf, err := ioutil.ReadFile(ca)
	if err != nil {
		return nil, nil, err
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(buf)
	pair, err := tls.LoadX509KeyPair(crt, pem)
	if err != nil {
		return nil, nil, err
	}
	return certPool, &pair, err

}

func connCheck(conn net.Conn) error {
	var sysErr error

	sysConn, ok := conn.(syscall.Conn)
	if !ok {
		return nil
	}
	rawConn, err := sysConn.SyscallConn()
	if err != nil {
		return err
	}

	err = rawConn.Read(func(fd uintptr) bool {
		var buf [1]byte
		n, err := syscall.Read(int(fd), buf[:])
		switch {
		case n == 0 && err == nil:
			sysErr = io.EOF
		case n > 0:
			sysErr = errUnexpectedRead
		case err == syscall.EAGAIN || err == syscall.EWOULDBLOCK:
			sysErr = nil
		default:
			sysErr = err
		}
		return true
	})
	if err != nil {
		return err
	}

	return sysErr
}
