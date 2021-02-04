package goproxy

import (
	"bufio"
	"crypto/tls"
	_ "fmt"
	"github.com/elazarl/goproxy/frame"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

func headerContains(header http.Header, name string, value string) bool {
	for _, v := range header[name] {
		for _, s := range strings.Split(v, ",") {
			if strings.EqualFold(value, strings.TrimSpace(s)) {
				return true
			}
		}
	}
	return false
}

func IsWebSocketRequest(r *http.Request) bool {
	return isWebSocketRequest(r)
}

func isWebSocketRequest(r *http.Request) bool {
	return headerContains(r.Header, "Connection", "upgrade") &&
		headerContains(r.Header, "Upgrade", "websocket")
}

func (proxy *ProxyHttpServer) serveWebsocketTLS(ctx *ProxyCtx, w http.ResponseWriter, req *http.Request, tlsConfig *tls.Config, clientConn *tls.Conn) {
	targetURL := url.URL{Scheme: "wss", Host: req.URL.Host, Path: req.URL.Path}

	// Connect to upstream
	targetConn, err := tls.Dial("tcp", targetURL.Host, tlsConfig)
	if err != nil {
		ctx.Warnf("Error dialing target site: %v", err)
		return
	}
	defer targetConn.Close()

	// Perform handshake
	if err := proxy.websocketHandshake(ctx, req, targetConn, clientConn); err != nil {
		ctx.Warnf("Websocket handshake error: %v", err)
		return
	}

	// Proxy wss connection
	proxy.proxyWebsocket(ctx, targetConn, clientConn)
}
func (proxy *ProxyHttpServer) ServeWebsocketNonDail(ctx *ProxyCtx, w http.ResponseWriter, req *http.Request, targetConn net.Conn) {
	// Connect to Client
	hj, ok := w.(http.Hijacker)
	if !ok {
		panic("httpserver does not support hijacking")
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		ctx.Warnf("Hijack error: %v", err)
		return
	}

	// Perform handshake
	if err := proxy.websocketHandshake(ctx, req, targetConn, clientConn); err != nil {
		ctx.Warnf("Websocket handshake error: %v", err)
		return
	}

	// Proxy ws connection
	proxy.proxyWebsocket(ctx, targetConn, clientConn)
}

func (proxy *ProxyHttpServer) serveWebsocket(ctx *ProxyCtx, w http.ResponseWriter, req *http.Request) {
	targetURL := url.URL{Scheme: "ws", Host: req.URL.Host, Path: req.URL.Path}

	targetConn, err := proxy.connectDial("tcp", targetURL.Host)
	if err != nil {
		ctx.Warnf("Error dialing target site: %v", err)
		return
	}
	defer targetConn.Close()

	// Connect to Client
	hj, ok := w.(http.Hijacker)
	if !ok {
		panic("httpserver does not support hijacking")
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		ctx.Warnf("Hijack error: %v", err)
		return
	}

	// Perform handshake
	if err := proxy.websocketHandshake(ctx, req, targetConn, clientConn); err != nil {
		ctx.Warnf("Websocket handshake error: %v", err)
		return
	}

	// Proxy ws connection
	proxy.proxyWebsocket(ctx, targetConn, clientConn)
}

func (proxy *ProxyHttpServer) websocketHandshake(ctx *ProxyCtx, req *http.Request, targetSiteConn io.ReadWriter, clientConn io.ReadWriter) error {
	// write handshake request to target
	err := req.Write(targetSiteConn)
	if err != nil {
		ctx.Warnf("Error writing upgrade request: %v", err)
		return err
	}

	targetTLSReader := bufio.NewReader(targetSiteConn)

	// Read handshake response from target
	resp, err := http.ReadResponse(targetTLSReader, req)
	if err != nil {
		ctx.Warnf("Error reading handhsake response  %v", err)
		return err
	}

	// Run response through handlers
	resp = proxy.filterResponse(resp, ctx)

	// Proxy handshake back to client
	err = resp.Write(clientConn)
	if err != nil {
		ctx.Warnf("Error writing handshake response: %v", err)
		return err
	}
	return nil
}

func (proxy *ProxyHttpServer) proxyWebsocket(ctx *ProxyCtx, dest io.ReadWriter, source io.ReadWriter) {
	errChan := make(chan error, 2)
	cp := func(dst io.Writer, src io.Reader) {
		reader := bufio.NewReader(src)
		writer := bufio.NewWriter(dst)
		for {
			hybiFacotry := frame.HybiFrameReaderFactory{Reader: reader}
			frameReader, err := hybiFacotry.NewFrameReader()
			if err != nil {
				ctx.Warnf("new frame reader error %v", err)
				break
			}
			payloadLen := frameReader.GetHeader().Length
			ctx.Logf("frame type is: %d , len is %d ,header length is %d",
				frameReader.PayloadType(), payloadLen)
			// 开始读取 frame 数据
			buf := make([]byte, payloadLen)
			nr, err := frameReader.Read(buf)
			if err != nil {
				ctx.Warnf("frame read error", err)
			}
			ctx.Logf("text msg is : %s ,buf len: %d, real len is: %d", string(buf), len(buf), nr)

			// 写入 frame
			frameWriter := frame.NewFrameWriter(writer, frameReader.GetHeader())
			nw, err := frameWriter.Write(buf)
			if err != nil {
				ctx.Warnf("frame write error %v", err)
			}
			ctx.Logf("write msg len is: %d", nw)

			if err != nil {
				ctx.Warnf("Websocket error: %v", err)
				errChan <- err
			}
		}

		//_, err := io.Copy(dst, src)
		//ctx.Warnf("Websocket error: %v", err)
		//errChan <- err
	}

	// Start proxying websocket data
	go cp(dest, source)
	go cp(source, dest)
	<-errChan
}
