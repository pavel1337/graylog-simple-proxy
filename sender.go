package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"time"
)

type Sender struct {
	ca           string
	crt          string
	key          string
	serverName   string
	insecure     bool
	remoteAddr   string
	workers      int
	debug        bool
	backoffCount int
	timeout      time.Duration

	hc *http.Client
}

func (s *Sender) Start(sendCh chan []byte, workers int) {
	c := &tls.Config{}

	if s.ca != "" {
		certPool, err := createCertPool(s.ca)
		if err != nil {
			log.Fatalln(err)
		}
		c.RootCAs = certPool
	}

	if s.crt != "" && s.key != "" {
		pair, err := createPair(s.crt, s.key)
		if err != nil {
			log.Fatalln(err)
		}
		c.Certificates = []tls.Certificate{*pair}
	}

	if s.insecure {
		c.InsecureSkipVerify = true
	}
	if s.serverName != "" {
		c.ServerName = s.serverName
	}

	s.hc = &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     c,
			MaxIdleConnsPerHost: s.workers,
		},
	}

	if err := checkCertificate(s.hc, s.remoteAddr); err != nil {
		log.Fatalln(err)
	}

	wg := sync.WaitGroup{}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go s.send(sendCh)
	}
	log.Println("sender started")
	wg.Wait()
}

func (s *Sender) send(sendCh chan []byte) {
	for m := range sendCh {
		if s.debug {
			log.Printf("new message to send: %s", trimMessage(m, 100))
		}
		var count int
		for {
			count++

			if count > s.backoffCount {
				log.Printf("message %s was not sent", trimMessage(m, 100))
				break
			}

			reader := bytes.NewReader(m)
			resp, err := s.hc.Post(s.remoteAddr, "", reader)
			if err != nil {
				log.Println(err)
				time.Sleep(time.Second)
				continue
			}
			if resp.StatusCode == 413 {
				log.Printf("discarding, status: %v", resp.Status)
				break
			}
			if resp.StatusCode != 202 {
				log.Printf("message is not processed, status: %v", resp.Status)
				time.Sleep(s.timeout)
				continue
			}
			resp.Body.Close()
			break
		}
	}
}

// checkCertificate checks the certificate of a TLS connection.
func checkCertificate(hc *http.Client, remoteAddr string) error {
	_, err := hc.Post(remoteAddr, "", nil)
	return err
}

// trimMessage to size int and return string
func trimMessage(m []byte, size int) string {
	if len(m) > size {
		return string(m[:size]) + "..."
	}
	return string(m) + "..."
}

// createCertPool creates a certificate pool from the given CA file.
// The files must be in PEM format.
func createCertPool(ca string) (*x509.CertPool, error) {
	buf, err := ioutil.ReadFile(ca)
	if err != nil {
		return nil, err
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(buf)
	return certPool, nil
}

// createPair creates a certificate pair from the given files.
// The files must be in PEM format.
func createPair(crt, pem string) (*tls.Certificate, error) {
	pair, err := tls.LoadX509KeyPair(crt, pem)
	if err != nil {
		return nil, err
	}
	return &pair, nil
}
