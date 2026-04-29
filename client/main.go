package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)


var ProtocolVersionV = [2]byte{0x03, 0x03}

func main() {
	// ═══════════════════════════════════════════════════════════════════════════
	// STEP 1: Establish TCP Connection
	// ═══════════════════════════════════════════════════════════════════════════
	conn, err := net.Dial("tcp", "localhost:8000")
	if err != nil {
		fmt.Printf("TCP connection failed to setup\n")
		panic(err)
	}
	fmt.Println("✓ TCP connection established to localhost:8000")

	// ═══════════════════════════════════════════════════════════════════════════
	// STEP 2: Build ClientHello Message
	// ═══════════════════════════════════════════════════════════════════════════
	var randomBytes [28]byte
	rand.Read(randomBytes[:])
	
	handshakeHash := sha256.New()

	random := RandomStruct{
		unixTime:    uint32(time.Now().Unix()),
		randomBytes: randomBytes,
	}

	clientHello := ClientHello{
		protocolV:          ProtocolVersionV,                        // TLS 1.2
		Random:             random,                                   // 32 bytes of randomness
		sessionId:          []byte{},                                 // Empty = new session (not resuming)
		cypherSuits:        []uint16{tls.TLS_RSA_WITH_AES_256_CBC_SHA}, // Cipher suite we support
		compressionMethods: []byte{0x00},                            // 0x00 = no compression
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// STEP 3: Wrap ClientHello in Handshake Protocol Layer
	// ═══════════════════════════════════════════════════════════════════════════
	clientHelloBytes := clientHello.serialize()
	l := len(clientHelloBytes)

	handshakeMessage := HandshakeMessage{
		MessageType: 0x01, // 0x01 = ClientHello
		length:      [3]byte{byte(l >> 16), byte(l >> 8), byte(l)},
		payload:     clientHelloBytes,
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// STEP 4: Wrap Handshake Message in TLS Record Layer
	// ═══════════════════════════════════════════════════════════════════════════

	handshakeBytes := handshakeMessage.serialize()
	
	handshakeHash.Write(handshakeBytes)
	
	tlsRecord := TLSRecord{
		contentType:   0x16, // 0x16 = Handshake
		protocolV:     ProtocolVersionV,
		payloadLength: uint16(len(handshakeBytes)),
		payload:       handshakeBytes,
	}

	tlsRecordBytes := tlsRecord.serialize()
	fmt.Printf("\n→ Sending ClientHello — %d bytes\n", len(tlsRecordBytes))
	conn.Write(tlsRecordBytes)

	// ═══════════════════════════════════════════════════════════════════════════
	// STEP 5: Read Server Response
	// ═══════════════════════════════════════════════════════════════════════════
	responseBuffer := make([]byte, 4096)
	_, err = conn.Read(responseBuffer)
	if err != nil {
		fmt.Println("Failed to read server response")
		panic(err)
	}
	respReader := bytes.NewReader(responseBuffer)

	// ───────────────────────────────────────────────────────────────────────────
	// STEP 5.1: Parse ServerHello
	// ───────────────────────────────────────────────────────────────────────────

	tlsRecord.parse(respReader)
	handshakeMessage.parse(bytes.NewReader(tlsRecord.payload))
	handshakeHash.Write(tlsRecord.payload) // Add to handshake hash
	
	serverHello := ServerHello{}
	serverHello.parse(bytes.NewReader(handshakeMessage.payload))

	fmt.Printf("\n← Received ServerHello:\n")
	fmt.Printf("  Protocol Version: 0x%02X%02X\n", serverHello.ProtocolVersion[0], serverHello.ProtocolVersion[1])
	fmt.Printf("  Random: %d bytes\n", 32)
	fmt.Printf("  Session ID: %d bytes\n", len(serverHello.SessionID))
	fmt.Printf("  Cipher Suite: 0x%04X\n", serverHello.CipherSuite)

	// ───────────────────────────────────────────────────────────────────────────
	// STEP 5.2: Parse Certificate
	// ───────────────────────────────────────────────────────────────────────────

	fmt.Println("\n← Receiving Certificate...")
	tlsRecord.parse(respReader)
	handshakeMessage.parse(bytes.NewReader(tlsRecord.payload))
	handshakeHash.Write(tlsRecord.payload) // Add to handshake hash
	
	certificates := Certificates{}
	certificateReader := bytes.NewReader(handshakeMessage.payload)
	certificates.parse(certificateReader)
	fmt.Printf("  Server public key extracted: %d-bit RSA\n", certificates.serverPublicKey.N.BitLen())

	// ───────────────────────────────────────────────────────────────────────────
	// STEP 5.3: Parse ServerHelloDone
	// ───────────────────────────────────────────────────────────────────────────

	fmt.Println("\n← Receiving ServerHelloDone...")
	tlsRecord.parse(respReader)
	handshakeMessage.parse(bytes.NewReader(tlsRecord.payload))
	handshakeHash.Write(tlsRecord.payload) // Add to handshake hash
	fmt.Printf("  MessageType: 0x%02X (ServerHelloDone)\n", handshakeMessage.MessageType)
	fmt.Printf("  Payload Length: %d bytes (empty)\n", handshakeMessage.length)

	// ═══════════════════════════════════════════════════════════════════════════
	// STEP 6: Generate and Send ClientKeyExchange
	// ═══════════════════════════════════════════════════════════════════════════

	fmt.Println("\n→ Generating premaster secret...")
	premasterKey := GeneratePremasterKey()
	encryptedPremaster := GenerateEncryptedMasterKey(certificates.serverPublicKey, premasterKey)
	fmt.Printf("  Premaster secret: 48 bytes\n")
	fmt.Printf("  Encrypted with RSA: %d bytes\n", len(encryptedPremaster))
	
	clientKeyExchange := ClientKeyExchange{
		encryptedPremasterLen: uint16(len(encryptedPremaster)),
		encryptedPremaster:    encryptedPremaster,
	}
	clientKeyExchangeBytes := clientKeyExchange.serialize()
	clientKeyExchangeLength := len(clientKeyExchangeBytes)
	
	// Wrap in HandshakeMessage (type 0x10 = ClientKeyExchange)
	clientKeyExchangeHandshake := HandshakeMessage{
		MessageType: 0x10, // 0x10 = ClientKeyExchange
		length:      [3]byte{byte(clientKeyExchangeLength >> 16), byte(clientKeyExchangeLength >> 8), byte(clientKeyExchangeLength)},
		payload:     clientKeyExchangeBytes,
	}
	clientKeyExchangeHandshakeBytes := clientKeyExchangeHandshake.serialize()
	handshakeHash.Write(clientKeyExchangeHandshakeBytes) // Add to handshake hash
	
	// Wrap in TLS Record
	clientKeyExchangeTLSRecord := TLSRecord{
		contentType:   0x16, // 0x16 = Handshake
		protocolV:     ProtocolVersionV,
		payloadLength: uint16(len(clientKeyExchangeHandshakeBytes)),
		payload:       clientKeyExchangeHandshakeBytes,
	}
	clientKeyExchangeTLSRecordBytes := clientKeyExchangeTLSRecord.serialize()
	
	fmt.Printf("\n→ Sending ClientKeyExchange — %d bytes\n", len(clientKeyExchangeTLSRecordBytes))
	conn.Write(clientKeyExchangeTLSRecordBytes)

	// ═══════════════════════════════════════════════════════════════════════════
	// STEP 7: Derive Master Secret and Session Keys
	// ═══════════════════════════════════════════════════════════════════════════
	// Both client and server now have the premaster secret.
	// They use it along with the random values exchanged earlier to derive:
	// 1. Master Secret (48 bytes) - using PRF with label "master secret"
	// 2. Key Block (136 bytes) - using PRF with label "key expansion"
	
	fmt.Println("\n→ Deriving master secret and session keys...")
	
	// Combine client and server random values
	clientRandom := append(
		binary.BigEndian.AppendUint32(nil, clientHello.Random.unixTime),
		clientHello.Random.randomBytes[:]...,
	)
	serverRandom := append(
		binary.BigEndian.AppendUint32(nil, serverHello.Random.unixTime),
		serverHello.Random.randomBytes[:]...,
	)
	
	// Derive master secret: PRF(premaster, "master secret", client_random + server_random)
	seed := append(clientRandom, serverRandom...)
	masterSecret := PRF(premasterKey, "master secret", seed, 48)
	fmt.Printf("  Master secret: 48 bytes\n")
	
	keyBlock := PRF(masterSecret, "key expansion", append(serverRandom, clientRandom...), 136)
	fmt.Printf("  Key block: 136 bytes\n")

	// Split the key block into individual keys (not used in this handshake-only implementation)
	_ = keyBlock[0:20]    // clientWriteMAC: HMAC-SHA1 key for signing client messages
	_ = keyBlock[20:40]   // serverWriteMAC: HMAC-SHA1 key for signing server messages
	_ = keyBlock[40:72]   // clientWriteKey: AES-256 key for encrypting client data
	_ = keyBlock[72:104]  // serverWriteKey: AES-256 key for encrypting server data
	_ = keyBlock[104:120] // clientWriteIV: Initialization vector for client AES-CBC
	_ = keyBlock[120:136] // serverWriteIV: Initialization vector for server AES-CBC
	
	fmt.Printf("  ✓ Session keys derived successfully\n")

	// ═══════════════════════════════════════════════════════════════════════════
	// STEP 8: Send ChangeCipherSpec
	// ═══════════════════════════════════════════════════════════════════════════
	// ChangeCipherSpec is a special message (not a handshake message) that tells
	// the server: "All future messages from me will be encrypted using the keys
	// we just derived."
	//
	
	changeCipherSpecTLSRecord := TLSRecord{
		contentType:   0x14, // 0x14 = ChangeCipherSpec (special content type)
		protocolV:     ProtocolVersionV,
		payloadLength: uint16(1),
		payload:       []byte{0x01}, // Payload is always a single byte: 0x01
	}

	changeCipherSpecTLSRecordBytes := changeCipherSpecTLSRecord.serialize()
	fmt.Printf("\n→ Sending ChangeCipherSpec — %d bytes\n", len(changeCipherSpecTLSRecordBytes))
	conn.Write(changeCipherSpecTLSRecordBytes)
	
	// ═══════════════════════════════════════════════════════════════════════════
	// STEP 9: Send Finished Message
	// ═══════════════════════════════════════════════════════════════════════════
	
	handshakeDigest := handshakeHash.Sum(nil) // Get SHA256 hash of all handshake messages
	verifyDataBytes := PRF(masterSecret, "client finished", handshakeDigest, 12)

	clientFinishedHandshake := HandshakeMessage{
		MessageType: 0x14, // 0x14 = Finished
		length:      [3]byte{byte(0), byte(0), byte(12)}, // 12 bytes of verify_data
		payload:     verifyDataBytes,
	}
	clientFinishedHandshakeBytes := clientFinishedHandshake.serialize()
	
	clientFinishedTLSRecord := TLSRecord{
		contentType:   0x16, // 0x16 = Handshake
		protocolV:     ProtocolVersionV,
		payloadLength: uint16(len(clientFinishedHandshakeBytes)),
		payload:       clientFinishedHandshakeBytes,
	}
	clientFinishedRecordBytes := clientFinishedTLSRecord.serialize()
	
	fmt.Printf("\n→ Sending Finished message — %d bytes\n", len(clientFinishedRecordBytes))
	fmt.Printf("  Verify data: 12 bytes (PRF of handshake hash)\n")
	conn.Write(clientFinishedRecordBytes)

	// ═══════════════════════════════════════════════════════════════════════════
	// STEP 10: Read Server's ChangeCipherSpec and Finished
	// ═══════════════════════════════════════════════════════════════════════════
	// The server will now send:
	// 1. ChangeCipherSpec - indicating it will encrypt future messages
	// 2. Finished - proving it has the correct master secret
	//
	// After this, the TLS handshake is complete and both sides can exchange
	// encrypted application data.
	
	fmt.Println("\n← Receiving server's final messages...")
	
	// Read ChangeCipherSpec
	tlsRecord.parse(respReader)
	fmt.Printf("  Received ContentType: 0x%02X (ChangeCipherSpec)\n", tlsRecord.contentType)
	fmt.Printf("  Payload: %d byte\n", tlsRecord.payloadLength)
	
	// Read Finished
	tlsRecord.parse(respReader)
	fmt.Printf("  Received ContentType: 0x%02X (Handshake - Finished)\n", tlsRecord.contentType)
	fmt.Printf("  Payload: %d bytes\n", tlsRecord.payloadLength)

	fmt.Println("\n✓ TLS 1.2 Handshake Complete!")
	fmt.Println("  Both client and server have agreed on:")
	fmt.Println("  - Cipher suite: TLS_RSA_WITH_AES_256_CBC_SHA")
	fmt.Println("  - Master secret (48 bytes)")
	fmt.Println("  - Session keys for encryption and authentication")
	fmt.Println("  Ready for encrypted communication!")
}
