package udpnet

import (
	"time"
)

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
	callback func([]byte, error)
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
