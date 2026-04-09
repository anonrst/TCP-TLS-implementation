package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
)

var ProtocolVersionV = [2]byte{0x03, 0x03} // TLS 1.2 (used in TLS 1.3 handshake)
type Extension struct {
	Type uint16
	Data []byte
}
type ServerHello struct {
	ProtocolVersion   [2]byte
	Random            Random
	SessionID         []byte
	CipherSuite       uint16
	CompressionMethod byte
	Extension         []Extension
}
type Random struct {
	UnixTime    uint32
	RandomBytes [28]byte
}

type ClientHello struct {
	ProtocolVersion    [2]byte
	Random             Random
	SessionID          []byte
	CipherSuites       []uint16
	CompressionMethods []byte
	Extensions         []Extension
}

type TLSRecord struct {
	ContentType     byte
	ProtocolVersion [2]byte
	Length          uint16
	Payload         []byte
}

type HandshakeMessage struct {
	MessageType byte
	Length      [3]byte
	Payload     []byte
}

func (h *HandshakeMessage) Parse(reader io.Reader) {
	binary.Read(reader, binary.BigEndian, &h.MessageType)
	binary.Read(reader, binary.BigEndian, &h.Length)
	h.Payload = make([]byte, int(h.Length[0])<<16|int(h.Length[1])<<8|int(h.Length[2])) //it left bit sifthing shiting
	reader.Read(h.Payload)
}

func (c *ClientHello) SerializeBody() []byte {
	buf := new(bytes.Buffer)

	// Version
	buf.Write(c.ProtocolVersion[:])

	// Random
	binary.Write(buf, binary.BigEndian, c.Random.UnixTime)
	buf.Write(c.Random.RandomBytes[:])

	// SessionID
	buf.WriteByte(uint8(len(c.SessionID)))
	buf.Write(c.SessionID)

	// CipherSuites
	binary.Write(buf, binary.BigEndian, uint16(len(c.CipherSuites)*2))
	for _, cs := range c.CipherSuites {
		binary.Write(buf, binary.BigEndian, cs)
	}

	// CompressionMethods
	buf.WriteByte(uint8(len(c.CompressionMethods)))
	buf.Write(c.CompressionMethods)

	// Extensions
	extBuf := new(bytes.Buffer)
	for _, ext := range c.Extensions {
		binary.Write(extBuf, binary.BigEndian, ext.Type)
		binary.Write(extBuf, binary.BigEndian, uint16(len(ext.Data)))
		extBuf.Write(ext.Data)
	}

	binary.Write(buf, binary.BigEndian, uint16(extBuf.Len()))
	buf.Write(extBuf.Bytes())

	return buf.Bytes()
}
func (c *ClientHello) Serialize() []byte {
	body := c.SerializeBody()
	l := len(body)
	buffer := new(bytes.Buffer)
	binary.Write(buffer, binary.BigEndian, byte(0x01))                                    //message type for CLinet Hello
	binary.Write(buffer, binary.BigEndian, [3]byte{byte(l >> 16), byte(l >> 8), byte(l)}) //bit manupulation
	binary.Write(buffer, binary.BigEndian, body)
	return buffer.Bytes()
}

func (t *TLSRecord) Serialize(payload []byte) []byte {
	buf := new(bytes.Buffer)

	buf.WriteByte(22)

	buf.Write(ProtocolVersionV[:])

	binary.Write(buf, binary.BigEndian, uint16(len(payload)))

	buf.Write(payload)

	return buf.Bytes()
}



func (s *ServerHello) Parse(reader io.Reader) {
	binary.Read(reader, binary.BigEndian, &s.ProtocolVersion)
	binary.Read(reader, binary.BigEndian, &s.Random.UnixTime)
	binary.Read(reader, binary.BigEndian, &s.Random.RandomBytes)

	var sessionIDLength byte = 0
	binary.Read(reader, binary.BigEndian, &sessionIDLength)
	s.SessionID = make([]byte, sessionIDLength)
	reader.Read(s.SessionID[:sessionIDLength])

	binary.Read(reader, binary.BigEndian, &s.CipherSuite)
	binary.Read(reader, binary.BigEndian, &s.CompressionMethod)
	var extensions []Extension
	var extensionBtesLen uint16
	binary.Read(reader, binary.BigEndian, &extensionBtesLen)
	bytesRead := 0
	for bytesRead < int(extensionBtesLen) { //Because Every length field in TLS tells you how many bytes follow,
		var ext Extension
		binary.Read(reader, binary.BigEndian, &ext.Type)
		var dataLen uint16
		binary.Read(reader, binary.BigEndian, &dataLen)
		ext.Data = make([]byte, dataLen)
		reader.Read(ext.Data)
		extensions = append(extensions, ext)
		bytesRead += 2 + 2 + int(dataLen)
	}
}
func (r *TLSRecord) Parse(reader io.Reader) { //this parses te server hello message
	binary.Read(reader, binary.BigEndian, &r.ContentType)
	binary.Read(reader, binary.BigEndian, &r.ProtocolVersion)
	binary.Read(reader, binary.BigEndian, &r.Length)
	r.Payload = make([]byte, int(r.Length))
	reader.Read(r.Payload)
}

type Certifficate struct {
	sererPublicKey *rsa.PublicKey
	Premaster = [48]byte;
}

func (C *Certifficate) ParseCertificates(reader io.Reader) []*x509.Certificate {
	certificates := []*x509.Certificate{}

	lengthBytes := make([]byte, 3)
	reader.Read(lengthBytes)
	totalLength := int(lengthBytes[0])<<16 | int(lengthBytes[1])<<8 | int(lengthBytes[2])

	read := 0
	for read < totalLength {
		reader.Read(lengthBytes)
		length := int(lengthBytes[0])<<16 | int(lengthBytes[1])<<8 | int(lengthBytes[2])

		certBytes := make([]byte, length)
		reader.Read(certBytes)

		certificate, err := x509.ParseCertificate(certBytes)
		if err != nil {
			panic(err.Error())
		}

		certificates = append(certificates, certificate)
		read += length + 3
	}
	C.sererPublicKey = certificates[0].PublicKey.(*rsa.PublicKey)
	fmt.Printf("pulicKey:= %T\n", C.sererPublicKey)

	return certificates
}

func (C *Certifficate) ClientKeyExchangePayloadB() []byte {
	premaster := make([]byte, 48) //first two byte will be client version will left will be random Premaster secret key
	premaster[0] = byte(0x03)
	premaster[1] = byte(0x03)
	rand.Read(premaster[2:])
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, C.sererPublicKey, premaster)
	if err != nil {
		panic(err)
	}
	ClientKeyExchangeP := new(bytes.Buffer)
	C.Premaster = premaster;
	binary.Write(ClientKeyExchangeP, binary.BigEndian, uint16(len(encrypted)))
	ClientKeyExchangeP.Write(encrypted)
	return ClientKeyExchangeP.Bytes()
}



