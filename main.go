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
	"reflect"
	"strings"
	"syscall"
	"time"
)

const IP_TRANSPARENT = 19

func main() {
	// http://wiki.squid-cache.org/Features/IPv6
	// http://wiki.squid-cache.org/Features/Tproxy4
	out := flag.String("out", "", "uplink http proxy address")
	in := flag.String("in", ":3128", "proxy https listen address")
	flag.Parse()

	ln, err := net.Listen("tcp", *in)
	if err != nil {
		panic(err)
	}
	fdv := reflect.Indirect(reflect.Indirect(reflect.ValueOf(ln)).FieldByName("fd")).FieldByName("sysfd").Int()
	if err := syscall.SetsockoptInt(int(fdv), syscall.SOL_IP, IP_TRANSPARENT, 1); err != nil {
		panic(err)
	}

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

func handle(con net.Conn, out string) {
	defer con.Close()

	laddr := con.LocalAddr().(*net.TCPAddr)

	outs := strings.Fields(out)
	if len(outs) == 0 && laddr.Port == 443 {
		for _, name := range []string{"HTTPS_PROXY", "https_proxy"} {
			if value := os.Getenv(name); len(value) > 0 {
				if strings.Index(value, "://") < 0 {
					outs = append(outs, value)
					break
				}
				if u, err := url.Parse(value); err == nil {
					outs = append(outs, u.Host)
					break
				}
			}
		}
	}
	if len(outs) == 0 {
		for _, name := range []string{"HTTP_PROXY", "http_proxy"} {
			if value := os.Getenv(name); len(value) > 0 {
				if strings.Index(value, "://") < 0 {
					outs = append(outs, value)
					break
				}
				if u, err := url.Parse(value); err == nil {
					outs = append(outs, u.Host)
					break
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
		req, err := http.ReadRequest(bufio.NewReader(con))
		if err != nil {
			if err != io.EOF {
				log.Print("ReadRequest", err)
			}
			return
		}

		// using Opaque and RawQuery is stable
		if len(req.URL.Scheme) == 0 {
			req.URL.Scheme = "http"
			if len(req.URL.Host) == 0 {
				req.URL.Host = req.Header.Get("Host")
			}
			if len(req.URL.Host) == 0 {
				req.URL.Host = laddr.IP.String()
			}
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
				} else if res, err := http.ReadResponse(bufio.NewReader(conOut), req); err != nil {
					return err
				} else {
					sent := make(chan bool)
					go func() {
						io.Copy(conOut, req.Body)
						close(sent)
					}()
					res.Write(con)
					_ = <-sent
					return nil
				}
			}(); err == nil {
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
				} else if res, err := http.ReadResponse(bufio.NewReader(conOut), req); err != nil {
					return err
				} else if res.StatusCode != 200 {
					return fmt.Errorf("proxy error %v", res)
				} else {
					sent := make(chan bool)
					go func() {
						io.Copy(conOut, con)
						close(sent)
					}()
					io.Copy(con, res.Body)
					_ = <-sent
					return nil
				}
			}(); err == nil {
				return
			}
		}
	}
	log.Printf("handle faild for %v", laddr)
}
