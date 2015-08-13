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
			go func(con net.Conn) {
				defer con.Close()
				if conOut, err := net.Dial("tcp", *out); err != nil {
					log.Printf("outgoing error %v", err)
				} else {
					defer conOut.Close()

					rout := bufio.NewReader(conOut)

					// tried here to use hostname from SSL ClientHello entry,
					// but wild clients did not support it.
					// like github.com/elazarl/goproxy
					// using github.com/inconshreveable/go-vhost
					req := &http.Request{
						Method: "CONNECT",
						Host:   con.LocalAddr().String(),
						URL:    &url.URL{},
					}
					if err := req.WriteProxy(conOut); err != nil {
						log.Printf("write proxy req failed %v", err)
						return
					}
					if res, err := http.ReadResponse(rout, req); err != nil {
						log.Printf("send proxy req failed %v", err)
					} else if res.StatusCode != 200 {
						log.Printf("connect failed %v", res.Status)
					} else {
						sent := make(chan bool)
						go func() {
							if _, err := io.Copy(conOut, con); err != nil {
								log.Printf("transport out error %v", err)
							}
							close(sent)
						}()
						if _, err := io.Copy(con, rout); err != nil {
							log.Printf("transport in error %v", err)
						}
						_ = <-sent
					}
				}
			}(con)
		}
	}
}
