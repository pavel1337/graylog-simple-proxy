package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"sync"

	"github.com/pavel1337/graylog-simple-proxy/udpnet"
)

func main() {
	local := flag.String("l", "localhost:12201", "Local addres string to listen")
	remote := flag.String("r", "graylog.example.com", "Remote graylog GELF input")
	insecure := flag.Bool("insecure", false, "Skip Certificate Verification")
	serverName := flag.String("server-name", "", "Server Name declared in certificate to verificate")
	ca := flag.String("ca", "", "Certificate Authority path")
	crt := flag.String("crt", "", "Client certificate path")
	key := flag.String("key", "", "Client key path")
	flag.Parse()
	certPool, pair, err := createCertPool(*ca, *crt, *key)
	if err != nil {
		log.Fatalln(err)
	}

	c := tls.Config{
		RootCAs:      certPool,
		Certificates: []tls.Certificate{*pair},
	}
	if *insecure {
		c.InsecureSkipVerify = true
	}
	if *serverName != "" {
		c.ServerName = *serverName
	}

	ch := make(chan []byte, 100)
	go sender(ch, *remote, c)

	if strings.Index(*local, "://") == -1 {
		*local = "udp://" + *local
	}

	listener, err := udpnet.NewListener(*local)
	if err != nil {
		log.Fatalln(err)
	}
	go listener.Listen()

	for ret := range listener.Done {
		switch val := ret.(type) {
		case *udpnet.FatalError:
			log.Fatalln(val)
		case error:
			log.Println(val)
		case []byte:
			_, message := val[:8], val[8:] // id omitted
			message = append(message, byte(0))
			ch <- message
		}
	}
}

func sender(ch chan []byte, addr string, c tls.Config) {
	wg := sync.WaitGroup{}
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			for {
				tlsconn, err := newTlsConnection(addr, &c)
				if err != nil {
					log.Println(err)
					continue
				}
				for m := range ch {
					tlsconn.Write(m)
				}
			}
			wg.Done()
		}()
	}
	wg.Wait()
}

func newTlsConnection(addr string, config *tls.Config) (*tls.Conn, error) {
	c, err := tls.DialWithDialer(&net.Dialer{}, "tcp", addr, config)
	if err != nil {
		return nil, err
	}
	return c, nil
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
