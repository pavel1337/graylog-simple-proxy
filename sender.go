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
	ca         string
	crt        string
	key        string
	serverName string
	insecure   bool
	remoteAddr string

	hc *http.Client
}

func (s *Sender) Start(sendCh chan []byte, workers int) {
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

	s.hc = &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     c,
			MaxIdleConnsPerHost: 100,
		},
	}

	wg := sync.WaitGroup{}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go s.send(sendCh)
	}
	wg.Wait()
}

func (s *Sender) send(sendCh chan []byte) {
	for m := range sendCh {
		for {
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
				time.Sleep(time.Second)
				continue
			}
			resp.Body.Close()
			break
		}
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
