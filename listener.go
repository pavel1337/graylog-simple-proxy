package main

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/sha1"
	"errors"
	"io"
	"log"
	"net"
	"regexp"
	"sync"
	"time"
)

var (
	// a pattern matching the connectionless protocols
	dsnPattern = regexp.MustCompile(`^(udp[4|6]?|unixgram|ip[4|6]?:[^:]+)://([^$]+)$`)
)

type FatalError struct {
	e error
}

func (f *FatalError) Error() string {
	return f.e.Error()
}

type Listener struct {
	network   string
	address   string
	conn      net.PacketConn
	lock      *sync.Mutex
	pool      *sync.Pool
	queue     map[[8]byte]*chunkMessage
	chunkChan chan chunk
	buffChan  chan buff
	Done      chan interface{}
}

type buff struct {
	buf []byte
	id  []byte
}

// NewListener is wrapper around the gelf protocol for connectionless protocols, udp, unixgram or ip
func NewListener(address string) (*Listener, error) {
	if match := dsnPattern.FindStringSubmatch(address); len(match) != 3 {
		return nil, errors.New("invalid (connectionless) address '" + address + "'")
	} else {
		return &Listener{
			address: match[2],
			network: match[1],
			lock:    new(sync.Mutex),
			Done:    make(chan interface{}, 5),
			queue:   make(map[[8]byte]*chunkMessage),
			pool: &sync.Pool{
				New: func() interface{} {
					return new(bytes.Buffer)
				},
			},
		}, nil
	}
}

func (u *Listener) Close() error {
	defer func() {
		u.conn = nil
	}()

	close(u.Done)

	if nil != u.conn {
		return u.conn.Close()
	} else {
		return nil
	}
}

func (u *Listener) Listen() {
	u.chunkChan = make(chan chunk, 1000)
	go u.parseChunck()

	u.buffChan = make(chan buff, 10000)
	go u.parseBuff()

	if err := u.connect(); err != nil {
		u.Done <- &FatalError{err}
		return
	}
	for {
		buf, id := make([]byte, 8192), make([]byte, 8, 8)
		n, _, err := u.conn.ReadFrom(buf) // address string is ignored here

		if err != nil {
			u.Done <- err
		} else if n < len(buf) {
			u.createId(buf, id)
			// log.Println(fmt.Sprintf("[%X] received %d bytes from '%s'", id, n, add.String()))
		}
		select {
		case u.buffChan <- buff{buf: buf[:n], id: id}: // Put 2 in the channel unless it is full
		default:
			log.Println("queue is full, discarding log message")
			buf = nil
			id = nil
		}
	}
}
func (u *Listener) createId(in []byte, out []byte) {
	hasher := sha1.New()
	seed, _ := time.Now().MarshalBinary()
	hasher.Write(seed)
	hasher.Write(in)
	copy(out, hasher.Sum(nil))
}

func (u *Listener) parseBuff() {
	for b := range u.buffChan {
		u.parse(b.buf, b.id)
	}
}

func (u *Listener) parse(buf []byte, id []byte) {
	switch {
	case buf[0] == 0x1e && buf[1] == 0x0f: // chunked
		u.chunkChan <- chunk{b: buf, sid: id}
		// u.parseChunck(buf, id)
	case buf[0] == 0x1f && buf[1] == 0x8b: // gzip
		if ret, err := u.unmarshalGzip(buf); err != nil {
			// log.Println(fmt.Sprintf("[%X] failed to decompress gzip stream", id))
			u.Done <- err
		} else {
			// log.Println(fmt.Sprintf("[%X] decompressed gzip srream", id))
			u.Done <- append(id[:], ret...)
		}
	case buf[0] == 0x78 && buf[1] == 0xe5, // zlib
		buf[0] == 0x78 && buf[1] == 0x9c,
		buf[0] == 0x78 && buf[1] == 0xda:

		if ret, err := u.unmarshalZlib(buf); err != nil {
			// log.Println(fmt.Sprintf("[%X] failed to decompress zlib stream", id))
			u.Done <- err
		} else {
			// log.Println(fmt.Sprintf("[%X] decompressed zlib stream", id))
			u.Done <- append(id[:], ret...)
		}
	default:
		// log.Println(fmt.Sprintf("[%X] uncompressed stream", id))
		u.Done <- append(id[:], buf...)
	}
}

func (u *Listener) parseChunck() {
	for chunk := range u.chunkChan {
		b := chunk.b
		sid := chunk.sid
		id, index, count := [8]byte{b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9]}, b[10], b[11]
		// log.Println(fmt.Sprintf("[%X] chunck %X %d/%d", sid, id, index+1, count))
		u.lock.Lock()
		if _, ok := u.queue[id]; !ok {
			u.queue[id] = NewChunkMessage(make([][]byte, count), u, id, sid)
		}
		u.queue[id].chunks[index] = b[12:]
		u.lock.Unlock()
	}
}

func (u *Listener) unmarshalGzip(b []byte) ([]byte, error) {
	buf := u.pool.Get().(*bytes.Buffer)
	defer u.pool.Put(buf)
	defer buf.Reset()
	buf.Write(b)
	reader, err := gzip.NewReader(buf)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return u.readAll(reader)
}

func (u *Listener) unmarshalZlib(b []byte) ([]byte, error) {
	buf := u.pool.Get().(*bytes.Buffer)
	defer u.pool.Put(buf)
	defer buf.Reset()
	buf.Write(b)
	reader, err := zlib.NewReader(buf)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return u.readAll(reader)
}

func (u *Listener) readAll(r io.Reader) ([]byte, error) {
	raw, buf := make([]byte, 0), make([]byte, 1024)
	for {
		n, err := r.Read(buf)
		raw = append(raw, buf[:n]...)
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return nil, err
			}
		}
	}
	return raw, nil
}

func (u *Listener) connect() (err error) {
	u.lock.Lock()
	defer u.lock.Unlock()
	if nil == u.conn {
		u.conn, err = net.ListenPacket(u.network, u.address)
	}
	return
}

type chunk struct {
	b   []byte
	sid []byte
}

type chunkMessage struct {
	end      time.Time
	ticker   *time.Ticker
	chunks   [][]byte
	listener *Listener
	id       [8]byte
	sid      []byte
}

func NewChunkMessage(ref [][]byte, listener *Listener, id [8]byte, sid []byte) *chunkMessage {
	message := &chunkMessage{
		chunks:   ref,
		sid:      sid,
		end:      time.Now().Add(5 * time.Second),
		ticker:   time.NewTicker(250 * time.Millisecond),
		listener: listener,
		id:       id,
	}
	go message.check()
	return message

}

func (c *chunkMessage) Close() {
	c.ticker.Stop()
}

func (c *chunkMessage) check() {
	defer c.ticker.Stop()
	for now := range c.ticker.C {
		c.listener.lock.Lock()

		if c.valid() {
			// log.Println(fmt.Sprintf("[%X] message %X complete", c.sid, c.id[:]))
			c.listener.parse(c.merge(), c.sid)
			delete(c.listener.queue, c.id)
			c.listener.lock.Unlock()
			return
		}
		// expires, all message should arrive within 5 seconds
		// http://docs.graylog.org/en/2.3/pages/gelf.html#chunking
		if c.end.Before(now) {
			// log.Println(fmt.Sprintf("[%X] timeout, discarding message %X", c.sid, c.id[:]))
			c.listener.lock.Unlock()
			return
		}
		c.listener.lock.Unlock()
	}
}

func (c chunkMessage) merge() []byte {
	var buf []byte
	for i := 0; i < len(c.chunks); i++ {
		buf = append(buf, c.chunks[i]...)
	}
	return buf
}

func (c chunkMessage) valid() bool {
	for i := 0; i < len(c.chunks); i++ {
		if len(c.chunks[i]) <= 0 {
			return false
		}
	}
	return true
}
