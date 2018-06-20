package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
)

const IP_TRANSPARENT = 19

func setIpTransparent(fd uintptr) {
	if err := syscall.SetsockoptInt(int(fd), syscall.SOL_IP, IP_TRANSPARENT, 1); err != nil {
		panic(err)
	}
}

func main() {
	// http://wiki.squid-cache.org/Features/IPv6
	// http://wiki.squid-cache.org/Features/Tproxy4
	out := flag.String("out", "", "uplink http proxy address")
	in := flag.String("in", ":3128", "proxy https listen address")
	flag.Parse()
	
	// TODO: use net.ListenConfig in Go 1.11
	if inAddr, err := net.ResolveTCPAddr("tcp", *in); err != nil{
		panic(err)
	} else if ln, err := net.ListenTCP("tcp", inAddr); err != nil {
		panic(err)
	} else if raw, err := ln.SyscallConn(); err != nil {
		panic(err)
	} else if err := raw.Control(setIpTransparent); err != nil {
		panic(err)
	} else {
		for {
			if con, err := ln.Accept(); err != nil {
				if eno, ok := err.(syscall.Errno); ok && eno.Temporary() {
					continue
				}
				panic(err)
			} else {
				go handle(con, *out)
			}
		}
	}
}

func getHostPort(spec string) string {
	if strings.Index(spec, "://") < 0 {
		return spec
	}
	if u, err := url.Parse(spec); err == nil {
		return u.Host
	}
	return ""
}

type TimedIo struct {
	Conn net.Conn
}

func (self TimedIo) Read(buf []byte) (int, error) {
	self.Conn.SetReadDeadline(time.Now().Add(time.Minute))
	return self.Conn.Read(buf)
}

func (self TimedIo) Write(buf []byte) (int, error) {
	self.Conn.SetWriteDeadline(time.Now().Add(time.Minute))
	return self.Conn.Write(buf)
}

func handle(con net.Conn, out string) {
	defer con.Close()

	laddr := con.LocalAddr().(*net.TCPAddr)

	var outs []string
	for _, o := range strings.Fields(out) {
		outs = append(outs, getHostPort(o))
	}
	if len(outs) == 0 && laddr.Port == 443 {
		for _, name := range []string{"HTTPS_PROXY", "https_proxy"} {
			if value := os.Getenv(name); len(value) > 0 {
				if o := getHostPort(value); len(o) > 0 {
					outs = append(outs, o)
				}
			}
		}
	}
	if len(outs) == 0 {
		for _, name := range []string{"HTTP_PROXY", "http_proxy"} {
			if value := os.Getenv(name); len(value) > 0 {
				if o := getHostPort(value); len(o) > 0 {
					outs = append(outs, o)
				}
			}
		}
	}

	var v4addrs []string
	var v6addrs []string
	for _, out := range outs {
		if host, port, err := net.SplitHostPort(out); err != nil {
			log.Print("proxy config %v error %v", out, err)
		} else if ips, err := net.LookupIP(host); err == nil {
			for _, ip := range ips {
				if ip.To4() != nil {
					v4addrs = append(v4addrs, net.JoinHostPort(ip.String(), port))
				} else {
					v6addrs = append(v6addrs, net.JoinHostPort(ip.String(), port))
				}
			}
		} else {
			log.Print(laddr, err)
		}
	}

	var addrs []string
	if laddr.IP.To4() != nil {
		addrs = append(v4addrs, v6addrs...)
	} else {
		addrs = append(v6addrs, v4addrs...)
	}

	switch laddr.Port {
	case 80:
		rcon := bufio.NewReader(TimedIo{con})

		getRequest := func() *http.Request {
			req, err := http.ReadRequest(rcon)
			if err != nil {
				if err == io.EOF {
					// pass
				} else if e, ok := err.(net.Error); ok && e.Timeout() {
					// pass
				} else {
					log.Print(laddr, fmt.Errorf("http.ReadRequest %v", err))
				}
				return nil
			}

			// using Opaque and RawQuery is stable
			if len(req.URL.Scheme) == 0 {
				req.URL.Scheme = "http"
				if len(req.URL.Host) == 0 {
					req.URL.Host = req.Host
				}
				if len(req.URL.Host) == 0 {
					req.URL.Host = laddr.IP.String()
				}
			}
			return req
		}

		var req *http.Request
		for _, addr := range addrs {
			if err := func() error {
				var conOut net.Conn
				var rconOut *bufio.Reader
				for {
					if req == nil {
						req = getRequest()
					}
					if req == nil {
						return nil
					}
					if conOut == nil {
						var e1 error
						conOut, e1 = net.DialTimeout("tcp", addr, 2*time.Second)
						if e1 != nil {
							return e1
						}
						rconOut = bufio.NewReader(TimedIo{conOut})
						defer conOut.Close()
					}

					if err := req.WriteProxy(conOut); err != nil {
						return err
					} else if res, err := http.ReadResponse(rconOut, req); err != nil {
						return err
					} else {
						sent := make(chan bool)
						go func() {
							io.Copy(TimedIo{conOut}, req.Body)
							close(sent)
						}()
						res.Write(con)
						_ = <-sent

						if "keep-alive" != req.Header.Get("Connection") || "keep-alive" != res.Header.Get("Connection") {
							return nil
						}
						req = nil
					}
				}
				return nil
			}(); err != nil {
				log.Print(laddr, err)
			} else {
				return
			}
		}
	case 443:
		// tried here to use hostname from SSL ClientHello entry,
		// but wild clients did not support it.
		// like github.com/elazarl/goproxy
		// using github.com/inconshreveable/go-vhost
		req := &http.Request{
			Method: "CONNECT",
			Host:   con.LocalAddr().String(),
			URL:    &url.URL{},
		}
		for _, addr := range addrs {
			if err := func() error {
				conOut, err := net.DialTimeout("tcp", addr, 2*time.Second)
				if err != nil {
					return err
				}
				defer conOut.Close()

				if err := req.WriteProxy(conOut); err != nil {
					return err
				} else if res, err := http.ReadResponse(bufio.NewReader(TimedIo{conOut}), req); err != nil {
					return err
				} else if res.StatusCode != 200 {
					return fmt.Errorf("proxy error %v", res)
				} else {
					sent := make(chan bool)
					go func() {
						io.Copy(TimedIo{conOut}, TimedIo{con})
						close(sent)
					}()
					io.Copy(TimedIo{con}, res.Body)
					_ = <-sent
					return nil
				}
			}(); err != nil {
				log.Print(laddr, err)
			} else {
				return
			}
		}
	}
	log.Printf("handle faild for %v %v", laddr, addrs)
}
