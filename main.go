package main

import (
	"flag"
	"log"
	"strings"
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

	// Initialize and start sender
	sender := Sender{
		ca:         *ca,
		crt:        *crt,
		key:        *key,
		serverName: *serverName,
		insecure:   *insecure,
		remoteAddr: *remote,
	}
	sendCh := make(chan []byte)
	go sender.Start(sendCh)

	if strings.Index(*local, "://") == -1 {
		*local = "udp://" + *local
	}

	listener, err := NewListener(*local)
	if err != nil {
		log.Fatalln(err)
	}
	go listener.Listen()

	for ret := range listener.Done {
		switch val := ret.(type) {
		case *FatalError:
			log.Fatalln(val)
		case error:
			log.Println(val)
		case []byte:
			_, message := val[:8], val[8:] // id omitted
			message = append(message, byte(0))
			sendCh <- message
		}
	}
}
