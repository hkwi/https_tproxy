package main

import (
	"bufio"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"syscall"
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
			go func(conIn net.Conn) {
				defer conIn.Close()
				if conOut, err := net.Dial("tcp", *out); err != nil {
					log.Printf("outgoing error %v", err)
				} else {
					defer conOut.Close()

					laddr := conIn.LocalAddr().(*net.TCPAddr)
					switch laddr.Port {
					case 80:
						req, err := http.ReadRequest(bufio.NewReader(conIn))
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
						if err := req.WriteProxy(conOut); err != nil {
							log.Printf("write proxy req failed %v", err)
							return
						}
						if res, err := http.ReadResponse(bufio.NewReader(conOut), req); err != nil {
							log.Printf("send proxy req failed %v", err)
							return
						} else {
							sent := make(chan bool)
							go func() {
								io.Copy(conOut, req.Body)
								close(sent)
							}()
							res.Write(conIn)
							_ = <-sent
						}
					case 443:
						// tried here to use hostname from SSL ClientHello entry,
						// but wild clients did not support it.
						// like github.com/elazarl/goproxy
						// using github.com/inconshreveable/go-vhost
						req := &http.Request{
							Method: "CONNECT",
							Host:   conIn.LocalAddr().String(),
							URL:    &url.URL{},
						}
						if err := req.WriteProxy(conOut); err != nil {
							log.Printf("write proxy req failed %v", err)
							return
						}
						if res, err := http.ReadResponse(bufio.NewReader(conOut), req); err != nil {
							log.Printf("send proxy req failed %v", err)
						} else if res.StatusCode != 200 {
							log.Printf("connect failed %v", res.Status)
						} else {
							sent := make(chan bool)
							go func() {
								io.Copy(conOut, con)
								close(sent)
							}()
							io.Copy(conIn, res.Body)
							_ = <-sent
						}
					}
				}
			}(con)
		}
	}
}
