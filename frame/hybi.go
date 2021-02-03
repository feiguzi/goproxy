// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package frame

// This file implements a protocol of hybi draft.
// http://tools.ietf.org/html/draft-ietf-hybi-thewebsocketprotocol-17

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"io"
	"strings"
)

const (
	ProtocolVersionHybi13    = 13
	ProtocolVersionHybi      = ProtocolVersionHybi13
	SupportedProtocolVersion = "13"

	ContinuationFrame = 0
	TextFrame         = 1
	BinaryFrame       = 2
	CloseFrame        = 8
	PingFrame         = 9
	PongFrame         = 10
	UnknownFrame      = 255

	DefaultMaxPayloadBytes = 32 << 20 // 32MB
)

const (
	websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

	closeStatusNormal            = 1000
	closeStatusGoingAway         = 1001
	closeStatusProtocolError     = 1002
	closeStatusUnsupportedData   = 1003
	closeStatusFrameTooLarge     = 1004
	closeStatusNoStatusRcvd      = 1005
	closeStatusAbnormalClosure   = 1006
	closeStatusBadMessageData    = 1007
	closeStatusPolicyViolation   = 1008
	closeStatusTooBigData        = 1009
	closeStatusExtensionMismatch = 1010

	maxControlFramePayloadLength = 125
)

type frameReader interface {
	// Reader is to read payload of the frame.
	io.Reader

	// PayloadType returns payload type.
	PayloadType() byte

	// HeaderReader returns a reader to read header of the frame.
	HeaderReader() io.Reader

	// TrailerReader returns a reader to read trailer of the frame.
	// If it returns nil, there is no trailer in the frame.
	TrailerReader() io.Reader

	GetHeader() hybiFrameHeader

	// Len returns total length of the frame, including header and trailer.
	Len() int
}

// frameWriter is an interface to write a WebSocket frame.
type frameWriter interface {
	// Writer is to write payload of the frame.
	io.WriteCloser
}

// ProtocolError represents WebSocket protocol errors.
type ProtocolError struct {
	ErrorString string
}

func (err *ProtocolError) Error() string { return err.ErrorString }

var (
	ErrBadMaskingKey         = &ProtocolError{"bad masking key"}
	ErrBadPongMessage        = &ProtocolError{"bad pong message"}
	ErrBadClosingStatus      = &ProtocolError{"bad closing status"}
	ErrUnsupportedExtensions = &ProtocolError{"unsupported extensions"}
	ErrNotImplemented        = &ProtocolError{"not implemented"}

	handshakeHeader = map[string]bool{
		"Host":                   true,
		"Upgrade":                true,
		"Connection":             true,
		"Sec-Websocket-Key":      true,
		"Sec-Websocket-Origin":   true,
		"Sec-Websocket-Version":  true,
		"Sec-Websocket-Protocol": true,
		"Sec-Websocket-Accept":   true,
	}
)

// A hybiFrameHeader is a frame header as defined in hybi draft.
type hybiFrameHeader struct {
	Fin        bool
	Rsv        [3]bool
	OpCode     byte
	Length     int64
	MaskingKey []byte

	data *bytes.Buffer
}

// A hybiFrameReader is a reader for hybi frame.
type hybiFrameReader struct {
	reader io.Reader

	header hybiFrameHeader
	pos    int64
	length int
}

func (frame *hybiFrameReader) GetHeader() hybiFrameHeader { return frame.header }

func (frame *hybiFrameReader) Read(msg []byte) (n int, err error) {
	n, err = io.ReadFull(frame.reader, msg)
	if frame.header.MaskingKey != nil {
		for i := 0; i < n; i++ {
			msg[i] = msg[i] ^ frame.header.MaskingKey[frame.pos%4]
			frame.pos++
		}
	}
	return n, err
}

func (frame *hybiFrameReader) PayloadType() byte { return frame.header.OpCode }

func (frame *hybiFrameReader) HeaderReader() io.Reader {
	if frame.header.data == nil {
		return nil
	}
	if frame.header.data.Len() == 0 {
		return nil
	}
	return frame.header.data
}

func (frame *hybiFrameReader) TrailerReader() io.Reader { return nil }

func (frame *hybiFrameReader) Len() (n int) { return frame.length }

// A hybiFrameReaderFactory creates new frame reader based on its frame type.
type HybiFrameReaderFactory struct {
	*bufio.Reader
}

// NewFrameReader reads a frame header from the connection, and creates new reader for the frame.
// See Section 5.2 Base Framing protocol for detail.
// http://tools.ietf.org/html/draft-ietf-hybi-thewebsocketprotocol-17#section-5.2
func (buf HybiFrameReaderFactory) NewFrameReader() (frame frameReader, err error) {
	hybiFrame := new(hybiFrameReader)
	frame = hybiFrame
	var header []byte
	var b byte
	// First byte. FIN/RSV1/RSV2/RSV3/OpCode(4bits)
	b, err = buf.ReadByte()
	if err != nil {
		return
	}
	header = append(header, b)
	hybiFrame.header.Fin = ((header[0] >> 7) & 1) != 0
	for i := 0; i < 3; i++ {
		j := uint(6 - i)
		hybiFrame.header.Rsv[i] = ((header[0] >> j) & 1) != 0
	}
	hybiFrame.header.OpCode = header[0] & 0x0f

	// Second byte. Mask/Payload len(7bits)
	b, err = buf.ReadByte()
	if err != nil {
		return
	}
	header = append(header, b)
	mask := (b & 0x80) != 0
	b &= 0x7f
	lengthFields := 0
	switch {
	case b <= 125: // Payload length 7bits.
		hybiFrame.header.Length = int64(b)
	case b == 126: // Payload length 7+16bits
		lengthFields = 2
	case b == 127: // Payload length 7+64bits
		lengthFields = 8
	}
	for i := 0; i < lengthFields; i++ {
		b, err = buf.ReadByte()
		if err != nil {
			return
		}
		if lengthFields == 8 && i == 0 { // MSB must be zero when 7+64 bits
			b &= 0x7f
		}
		header = append(header, b)
		hybiFrame.header.Length = hybiFrame.header.Length*256 + int64(b)
	}
	if mask {
		// Masking key. 4 bytes.
		for i := 0; i < 4; i++ {
			b, err = buf.ReadByte()
			if err != nil {
				return
			}
			header = append(header, b)
			hybiFrame.header.MaskingKey = append(hybiFrame.header.MaskingKey, b)
		}
	}
	hybiFrame.reader = io.LimitReader(buf.Reader, hybiFrame.header.Length)
	hybiFrame.header.data = bytes.NewBuffer(header)
	hybiFrame.length = len(header) + int(hybiFrame.header.Length)
	return
}

// A HybiFrameWriter is a writer for hybi frame.
type hybiFrameWriter struct {
	writer *bufio.Writer

	header *hybiFrameHeader
}

func NewFrameWriter(writer *bufio.Writer, header hybiFrameHeader) *hybiFrameWriter {
	return &hybiFrameWriter{
		writer: writer,
		header: &header,
	}
}

func (frame *hybiFrameWriter) Write(msg []byte) (n int, err error) {
	var header []byte
	var b byte
	if frame.header.Fin {
		b |= 0x80
	}
	for i := 0; i < 3; i++ {
		if frame.header.Rsv[i] {
			j := uint(6 - i)
			b |= 1 << j
		}
	}
	b |= frame.header.OpCode
	header = append(header, b)
	if frame.header.MaskingKey != nil {
		b = 0x80
	} else {
		b = 0
	}
	lengthFields := 0
	length := len(msg)
	switch {
	case length <= 125:
		b |= byte(length)
	case length < 65536:
		b |= 126
		lengthFields = 2
	default:
		b |= 127
		lengthFields = 8
	}
	header = append(header, b)
	for i := 0; i < lengthFields; i++ {
		j := uint((lengthFields - i - 1) * 8)
		b = byte((length >> j) & 0xff)
		header = append(header, b)
	}
	if frame.header.MaskingKey != nil {
		if len(frame.header.MaskingKey) != 4 {
			return 0, ErrBadMaskingKey
		}
		header = append(header, frame.header.MaskingKey...)
		frame.writer.Write(header)
		data := make([]byte, length)
		for i := range data {
			data[i] = msg[i] ^ frame.header.MaskingKey[i%4]
		}
		frame.writer.Write(data)
		err = frame.writer.Flush()
		return length, err
	}
	frame.writer.Write(header)
	frame.writer.Write(msg)
	err = frame.writer.Flush()
	return length, err
}

func (frame *hybiFrameWriter) Close() error { return nil }

type hybiFrameWriterFactory struct {
	*bufio.Writer
	needMaskingKey bool
}

func (buf hybiFrameWriterFactory) NewFrameWriter(payloadType byte) (frame frameWriter, err error) {
	frameHeader := &hybiFrameHeader{Fin: true, OpCode: payloadType}
	if buf.needMaskingKey {
		frameHeader.MaskingKey, err = generateMaskingKey()
		if err != nil {
			return nil, err
		}
	}
	return &hybiFrameWriter{writer: buf.Writer, header: frameHeader}, nil
}

// generateMaskingKey generates a masking key for a frame.
func generateMaskingKey() (maskingKey []byte, err error) {
	maskingKey = make([]byte, 4)
	if _, err = io.ReadFull(rand.Reader, maskingKey); err != nil {
		return
	}
	return
}

// generateNonce generates a nonce consisting of a randomly selected 16-byte
// value that has been base64-encoded.
func generateNonce() (nonce []byte) {
	key := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}
	nonce = make([]byte, 24)
	base64.StdEncoding.Encode(nonce, key)
	return
}

// removeZone removes IPv6 zone identifer from host.
// E.g., "[fe80::1%en0]:8080" to "[fe80::1]:8080"
func removeZone(host string) string {
	if !strings.HasPrefix(host, "[") {
		return host
	}
	i := strings.LastIndex(host, "]")
	if i < 0 {
		return host
	}
	j := strings.LastIndex(host[:i], "%")
	if j < 0 {
		return host
	}
	return host[:j] + host[i:]
}

// getNonceAccept computes the base64-encoded SHA-1 of the concatenation of
// the nonce ("Sec-WebSocket-Key" value) with the websocket GUID string.
func getNonceAccept(nonce []byte) (expected []byte, err error) {
	h := sha1.New()
	if _, err = h.Write(nonce); err != nil {
		return
	}
	if _, err = h.Write([]byte(websocketGUID)); err != nil {
		return
	}
	expected = make([]byte, 28)
	base64.StdEncoding.Encode(expected, h.Sum(nil))
	return
}
