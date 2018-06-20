https_tproxy
------------
transparent proxy gateway program that transmits http, https traffics into specified uplink http proxy. `CONNECT` method will be transparently prepared for https connections.

```
GOMAXPROCS=4 https_proxy -in [::]:3128 -out gw.local:8080
```

If omitted, `in` defaults to :3128 by default to which port you'll set the tproxy iptables rule. You can use HTTP_PROXY, HTTPS_PROXY environment variables to set `out` uplink proxy.

```
HTTP_PROXY=http://gw_http.local:8080 HTTPS_PROXY=http://gw_https.local:8080 GOMAXPROCS=4 https_proxy
```

Quick how-to is [available](http://qiita.com/kwi/items/b7c770d6b92c16c334fb) in Japanese.
