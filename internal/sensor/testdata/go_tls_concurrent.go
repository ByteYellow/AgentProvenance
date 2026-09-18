// This fixture deliberately grows a goroutine stack inside crypto/tls.Read.
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
)

type growingConn struct {
	net.Conn
	grow bool
}

func (c *growingConn) Read(p []byte) (int, error) {
	if c.grow {
		if growStack(128) == 255 {
			panic("unreachable")
		}
	}
	return c.Conn.Read(p)
}

//go:noinline
func growStack(depth int) byte {
	var block [4096]byte
	block[depth] = byte(depth)
	if depth > 0 {
		return growStack(depth-1) ^ block[depth]
	}
	runtime.Gosched()
	return block[depth]
}

type result struct {
	Conn string `json:"conn"`
	Data []byte `json:"data"`
	Err  string `json:"error,omitempty"`
}

func main() {
	runtime.GOMAXPROCS(2)
	if len(os.Args) != 2 {
		panic("usage: go-tls-concurrent host:port")
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	enc := json.NewEncoder(os.Stdout)
	for id := 0; id < 32; id++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			raw, err := net.Dial("tcp", os.Args[1])
			if err != nil {
				panic(err)
			}
			transport := &growingConn{Conn: raw}
			conn := tls.Client(transport, &tls.Config{InsecureSkipVerify: true}) // local test server
			defer conn.Close()
			if err := conn.Handshake(); err != nil {
				panic(err)
			}
			transport.grow = true
			if _, err := fmt.Fprintf(conn, "GET /reply-%02d HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n", id); err != nil {
				panic(err)
			}
			var response []byte
			var buf [512]byte
			for {
				for i := range buf {
					buf[i] = '~' // must never leak unused capacity into a TLS event
				}
				n, err := conn.Read(buf[:])
				response = append(response, buf[:n]...)
				if err != nil {
					if err != io.EOF {
						panic(err)
					}
					break
				}
			}
			mu.Lock()
			if err := enc.Encode(result{Conn: fmt.Sprintf("%p", conn), Data: response}); err != nil {
				panic(err)
			}
			mu.Unlock()
		}(id)
	}
	wg.Wait()
}
