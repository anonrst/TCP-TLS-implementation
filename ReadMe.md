# TLS 1.2 (Transport Layer Security)

> This document covers a TLS 1.2 implementation.

TLS is built on top of TCP. Its main purpose is to encrypt the raw data sent over TCP so that no one can read it during transmission. Its job is not to organize data packets — that is TCP's responsibility.

To establish a secure connection, TLS performs a series of handshakes between client and server. Every handshake message is wrapped inside a `HandshakeMessage`, and that `HandshakeMessage` is wrapped inside a `TLSRecord`. This makes `TLSRecord` the outermost wrapper of every request.
---

## Serialization

Before any data is transmitted, it must be serialized means converted from structured objects into raw bytes, becuase TCP supports raw bytes to ransfer.

---

## TLS Record

Every message sent during a TLS  message is sent inside a `TLSRecord`. Think of it as the envelope around every transmission: it tells the receiver what type of content is, protocol version and length of payload in bytes, and then carries the payload itself.

```go
type TLSRecord struct {
    ContentType     byte
    ProtocolVersion [2]byte
    Length          uint16
    Payload         []byte
}
```

The `ContentType` field in every TLSRecord tells the receiver how to interpret the payload:

| Hex    | Content Type     |
|--------|------------------|
| `0x14` | ChangeCipherSpec |
| `0x15` | Alert            |
| `0x16` | Handshake        |
| `0x17` | ApplicationData  |

Only `TLSRecord`s with `ContentType = 0x16` contain a `HandshakeMessage` inside their payload. Other content types — like `ChangeCipherSpec` — carry their payload directly, without a `HandshakeMessage` wrapper.

Breaking it down: `0x14` is the `ContentType` (ChangeCipherSpec), `0x03 0x03` is the protocol version (TLS 1.2), `0x00 0x01` is the payload length (1 byte), and `0x01` is the payload itself.

---

## Handshake Message

When a `TLSRecord` has `ContentType = 0x16`, its payload contains a `HandshakeMessage`. This is a second layer of wrapping that identifies the specific type of handshake step being performed and carries its data.

```go
type HandshakeMessage struct {
    MessageType byte
    Length      [3]byte
    Payload     []byte
}
```

The nesting looks like this:

```
TLSRecord
    └── HandshakeMessage
            └── ClientHello / ServerHello / Certificate / ... (actual payload)
```

### Handshake Message Types

The table below covers only the message types relevant to this TLS 1.2 RSA implementation. TLS 1.3-only types (`NewSessionTicket`, `EncryptedExtensions`) and mutual-TLS types (`CertificateRequest`, `CertificateVerify`) are intentionally excluded.

| Value | Message Type      | Direction / Note                                                              |
|-------|-------------------|-------------------------------------------------------------------------------|
| 0     | HelloRequest      | Rare / mostly obsolete                                                        |
| 1     | ClientHello       | Client → Server                                                               |
| 2     | ServerHello       | Server → Client                                                               |
| 11    | Certificate       | Server sends its certificate chain after ServerHello                          |
| 12    | ServerKeyExchange | DHE/ECDHE suites only — **not sent in RSA key exchange (this impl)**          |
| 14    | ServerHelloDone   | Signals the end of the server's hello messages                                |
| 16    | ClientKeyExchange | Client sends the RSA-encrypted pre-master secret                              |
| 20    | Finished          | Both sides — first message protected by the negotiated session keys           |

---

## Go Structs

```go
type Extension struct {
    Type uint16
    Data []byte
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

type ServerHello struct {
    ProtocolVersion   [2]byte
    Random            Random
    SessionID         []byte
    CipherSuite       uint16
    CompressionMethod byte
    Extension         []Extension
}
```

### Cipher Suite

A `CipherSuite` is a combination of algorithms that both client and server agree to use for both asymetric and sysmetric session setup. The client sends a list of supported cipher suites in `ClientHello`, and the server picks one and echoes it back in `ServerHello`.

This implementation uses `TLS_RSA_WITH_AES_256_CBC_SHA`, which breaks down as:

| Segment       | Algorithm           | Role                                                                                  |
|---------------|---------------------|---------------------------------------------------------------------------------------|
| `RSA`         | RSA                 | Key exchange — the client encrypts the pre-master secret with the server's public key |
| `AES_256_CBC` | AES-256 in CBC mode | Symmetric cipher — encrypts all application data after `ChangeCipherSpec`             |
| `SHA`         | HMAC-SHA1           | MAC algorithm — verifies the integrity of every encrypted record                      |

### SessionID and Session Resumption

The `SessionID` field in both `ClientHello` and `ServerHello` supports session resumption. On the first connection the client sends an empty `SessionID`. The server assigns one and returns it in `ServerHello`. If the same client reconnects later and sends that `SessionID` in a new `ClientHello`, the server can recognize it, skip the full handshake, and directly reuse the previously negotiated master secret — avoiding the expensive RSA decryption step again.

---

## The TLS 1.2 Handshake

### Step 1 — ClientHello

The client initiates the handshake by sending a `ClientHello` record. This contains a 32-byte `Random` value (4 bytes Unix timestamp + 28 random bytes) and a list of cipher suites the client supports.

### Step 2 — Server responds with three records back-to-back

The server replies with three `TLSRecord`s sent in a single response:

1. **ServerHello** — Contains the server's chosen cipher suite and its own 32-byte `Random` value.
2. **Certificate** — Contains the server's certificate chain. The first certificate in the chain holds the server's public key. Every certificate in the chain is signed by the one above it, up to a trusted root.
3. **ServerHelloDone** — Signals that the server is done sending its handshake messages and it is now the client's turn.

### Step 3 — ClientKeyExchange

The client takes the server's public key from the first certificate and uses it to encrypt a 48-byte **pre-master secret**. This encrypted value is sent to the server inside a `ClientKeyExchange` handshake record. Only the server can decrypt it using its corresponding private key.

At this point, both sides have the pre-master secret. They each independently derive the same 48-byte **master secret** from it. From the master secret, both sides derive a 136-byte **key block** containing all the session keys needed to encrypt and verify data for the rest of the connection.

### Step 4 — ChangeCipherSpec (Client)

The client sends a `ChangeCipherSpec` record (`ContentType = 0x14`). This signals that the client is switching from asymmetric encryption — which uses the server's public/private key pair — to symmetric encryption using `AES_256_CBC`, where a single shared session key is used for both encryption and decryption.

### Step 5 — Finished (Client)

The client sends a `Finished` handshake record, encrypted with the newly derived session keys. This is the first message protected by symmetric encryption.

### Step 6 — ChangeCipherSpec + Finished (Server)

The server sends its own `ChangeCipherSpec` record, agreeing to switch to symmetric encryption. It then sends its own `Finished` record. Once both sides have exchanged `Finished` records, the handshake is complete and encrypted application data transmission can begin.

### Full Handshake Diagram

```
Client                          Server
  │                               │
  │──── ClientHello ─────────────▶│
  │                               │
  │◀─── ServerHello ──────────────│
  │◀─── Certificate ──────────────│
  │◀─── ServerHelloDone ──────────│
  │                               │
  │──── ClientKeyExchange ───────▶│
  │──── ChangeCipherSpec ────────▶│
  │──── Finished ────────────────▶│
  │                               │
  │◀─── ChangeCipherSpec ─────────│
  │◀─── Finished ─────────────────│
  │                               │
  │  [Encrypted Application Data] │
```