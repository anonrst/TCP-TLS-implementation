package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
)

type Extension struct {
	Type uint16
	Data []byte
}

type RandomStruct struct {
	unixTime    uint32 // 4 byte
	randomBytes [28]byte
}

type ClientHello struct {
	protocolV          [2]byte
	Random             RandomStruct
	sessionId          []byte
	cypherSuits        []uint16 // list of encryption algorithms
	compressionMethods []byte
	extensions         []Extension
}

func (c *ClientHello) serialize() []byte {
	buffer := new(bytes.Buffer)

	buffer.Write(c.protocolV[:])

	binary.Write(buffer, binary.BigEndian, c.Random.unixTime)
	buffer.Write(c.Random.randomBytes[:])

	buffer.WriteByte(uint8(len(c.sessionId)))
	buffer.Write(c.sessionId)

	binary.Write(buffer, binary.BigEndian, uint16(len(c.cypherSuits)*2))
	for _, cs := range c.cypherSuits {
		binary.Write(buffer, binary.BigEndian, cs)
	}

	buffer.WriteByte(uint8(len(c.compressionMethods)))
	buffer.Write(c.compressionMethods)

	exts := new(bytes.Buffer)
	for _, ex := range c.extensions {
		binary.Write(exts, binary.BigEndian, ex.Type)
		binary.Write(exts, binary.BigEndian, uint16(len(ex.Data)))
		exts.Write(ex.Data)
	}

	binary.Write(buffer, binary.BigEndian, uint16(exts.Len()))
	buffer.Write(exts.Bytes())

	return buffer.Bytes()
}

type ServerHello struct {
	ProtocolVersion   [2]byte
	Random            RandomStruct
	SessionID         []byte
	CipherSuite       uint16
	CompressionMethod byte
	Extension         []Extension
}

func (s *ServerHello) parse(reader io.Reader) {
	// 2 bytes protocol version
	binary.Read(reader, binary.BigEndian, &s.ProtocolVersion)

	// 4 bytes unix time + 28 bytes random
	binary.Read(reader, binary.BigEndian, &s.Random.unixTime)
	binary.Read(reader, binary.BigEndian, &s.Random.randomBytes)

	// 1 byte session id length then that many bytes of session id
	var sessionIDLen byte
	binary.Read(reader, binary.BigEndian, &sessionIDLen)
	s.SessionID = make([]byte, sessionIDLen)
	reader.Read(s.SessionID)

	// 2 bytes cipher suite server picked
	binary.Read(reader, binary.BigEndian, &s.CipherSuite)

	// 1 byte compression method server picked
	binary.Read(reader, binary.BigEndian, &s.CompressionMethod)

	// 2 bytes total length of all extensions
	var extensionsLen uint16
	binary.Read(reader, binary.BigEndian, &extensionsLen)

	// read extensions until all extensionsLen bytes are consumed
	bytesRead := 0
	for bytesRead < int(extensionsLen) {
		var ext Extension

		// 2 bytes extension type
		binary.Read(reader, binary.BigEndian, &ext.Type)

		// 2 bytes length of this extension's data
		var dataLen uint16
		binary.Read(reader, binary.BigEndian, &dataLen)

		// that many bytes of extension data
		ext.Data = make([]byte, dataLen)
		reader.Read(ext.Data)

		s.Extension = append(s.Extension, ext)

		// 2 type + 2 length + data
		bytesRead += 2 + 2 + int(dataLen)
	}
}

type HandshakeMessage struct {
	MessageType byte
	length      [3]byte
	payload     []byte
}

func (HM *HandshakeMessage) serialize() []byte {
	buffer := new(bytes.Buffer)
	buffer.WriteByte(HM.MessageType)
	buffer.Write(HM.length[:])
	buffer.Write(HM.payload)
	return buffer.Bytes()
}

func (HM *HandshakeMessage) parse(reader io.Reader) {
	binary.Read(reader, binary.BigEndian, &HM.MessageType)
	binary.Read(reader, binary.BigEndian, &HM.length)
	payloadLength := int(HM.length[0])<<16 | int(HM.length[1])<<8 | int(HM.length[2])
	HM.payload = make([]byte, payloadLength)
	reader.Read(HM.payload)
}

type TLSRecord struct {
	contentType   byte
	protocolV     [2]byte
	payloadLength uint16
	payload       []byte
}

func (TLS *TLSRecord) serialize() []byte {
	buffer := new(bytes.Buffer)
	buffer.WriteByte(TLS.contentType)
	buffer.Write(TLS.protocolV[:])
	binary.Write(buffer, binary.BigEndian, TLS.payloadLength)
	buffer.Write(TLS.payload)
	return buffer.Bytes()
}

func (TLS *TLSRecord) parse(reader io.Reader) {
	binary.Read(reader, binary.BigEndian, &TLS.contentType)
	binary.Read(reader, binary.BigEndian, &TLS.protocolV)
	binary.Read(reader, binary.BigEndian, &TLS.payloadLength)
	TLS.payload = make([]byte, TLS.payloadLength)
	reader.Read(TLS.payload)
}

type Certificates struct {
	serverPublicKey *rsa.PublicKey
	certificates    []*x509.Certificate
}

func (C *Certificates) parse(reader io.Reader) {
	certificates := []*x509.Certificate{}
	lengthBytes := make([]byte, 3)
	reader.Read(lengthBytes)
	payloadLength := int(lengthBytes[0])<<16 | int(lengthBytes[1])<<8 | int(lengthBytes[2])

	totalRead := 0
	for totalRead < payloadLength {
		reader.Read(lengthBytes)

		certificateLength := int(lengthBytes[0])<<16 | int(lengthBytes[1])<<8 | int(lengthBytes[2])

		certificatePayloadBuff := make([]byte, certificateLength)
		reader.Read(certificatePayloadBuff)
		parsedCertificateStruct, err := x509.ParseCertificate(certificatePayloadBuff)
		if err != nil {
			fmt.Println("Failed to parse certificate")
			panic(err)
		}
		fmt.Printf("============ CERTIFICATE =========================\n")
		fmt.Printf("Certificate public key: %v\n", parsedCertificateStruct.PublicKey)
		fmt.Printf("Certificate issuer name: %v\n", parsedCertificateStruct.Issuer.CommonName)
		fmt.Printf("Certificate expiry time: %v\n\n\n", parsedCertificateStruct.NotAfter)
		certificates = append(certificates, parsedCertificateStruct)
		totalRead += 3 + certificateLength
	}
	C.serverPublicKey = certificates[0].PublicKey.(*rsa.PublicKey)
}

type ClientKeyExchange struct {
	encryptedPremasterLen uint16
	encryptedPremaster    []byte
}

func (C *ClientKeyExchange) serialize() []byte {
	buffer := new(bytes.Buffer)
	binary.Write(buffer, binary.BigEndian, C.encryptedPremasterLen)
	buffer.Write(C.encryptedPremaster)
	return buffer.Bytes()
}
func GeneratePremasterKey() []byte {
	premasterBuffer := make([]byte, 48) // premaster key is TLS version (2 bytes) + random bytes (46 bytes)
	premasterBuffer[0] = 0x03
	premasterBuffer[1] = 0x03
	rand.Read(premasterBuffer[2:])
	return premasterBuffer
}

func GenerateEncryptedMasterKey(serverPublicKey *rsa.PublicKey, premaster []byte) []byte {
	encryptedPremaster, err := rsa.EncryptPKCS1v15(rand.Reader, serverPublicKey, premaster)
	if err != nil {
		fmt.Println("Failed to generate encrypted premaster key")
		panic(err)
	}
	return encryptedPremaster
}

// hmacSHA256 takes a key and data, runs HMAC-SHA256, and returns exactly 32 bytes
func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// pSHA256 is the PRF expansion function that repeatedly calls hmacSHA256 until it generates the required length
func pSHA256(secret, seed []byte, length int) []byte {
	var result []byte
	a := seed // A(0) = seed
	for len(result) < length {
		a = hmacSHA256(secret, a)                                   // A(i) = HMAC(secret, A(i-1))
		result = append(result, hmacSHA256(secret, append(a, seed...))...)
	}
	return result[:length]
}

// PRF is the Pseudo-Random Function that generates keying material of the required length
func PRF(secret []byte, label string, seed []byte, length int) []byte {
	labelAndSeed := append([]byte(label), seed...)
	return pSHA256(secret, labelAndSeed, length)
}
