//go:build with_utls

package tls

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	utls "github.com/metacubex/utls"
)

const testRealityKeyShareGroupsRecordTimeout = 2 * time.Second

// readClientHelloKeyShareGroups reads a single TLS record from conn, parses the
// ClientHello inside it and returns the key_share extension's client group list.
func readClientHelloKeyShareGroups(conn net.Conn) ([]uint16, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	if header[0] != 22 {
		return nil, fmt.Errorf("unexpected record type %d", header[0])
	}
	record := make([]byte, int(binary.BigEndian.Uint16(header[3:5])))
	if _, err := io.ReadFull(conn, record); err != nil {
		return nil, err
	}
	// Handshake header: type(1) + length(3)
	if len(record) < 4 || record[0] != 1 {
		return nil, errors.New("unexpected handshake type, not ClientHello")
	}
	body := record[4:]
	// legacy_version(2) + random(32)
	if len(body) < 34 {
		return nil, io.ErrUnexpectedEOF
	}
	body = body[34:]
	// legacy_session_id
	if len(body) < 1 {
		return nil, io.ErrUnexpectedEOF
	}
	sessionIDLen := int(body[0])
	if len(body) < 1+sessionIDLen {
		return nil, io.ErrUnexpectedEOF
	}
	body = body[1+sessionIDLen:]
	// cipher_suites
	if len(body) < 2 {
		return nil, io.ErrUnexpectedEOF
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(body[:2]))
	if len(body) < 2+cipherSuitesLen {
		return nil, io.ErrUnexpectedEOF
	}
	body = body[2+cipherSuitesLen:]
	// legacy_compression_methods
	if len(body) < 1 {
		return nil, io.ErrUnexpectedEOF
	}
	compressionLen := int(body[0])
	if len(body) < 1+compressionLen {
		return nil, io.ErrUnexpectedEOF
	}
	body = body[1+compressionLen:]
	// extensions
	if len(body) < 2 {
		return nil, io.ErrUnexpectedEOF
	}
	extensionsLen := int(binary.BigEndian.Uint16(body[:2]))
	if len(body) < 2+extensionsLen {
		return nil, io.ErrUnexpectedEOF
	}
	extensions := body[2 : 2+extensionsLen]
	for len(extensions) >= 4 {
		extensionType := binary.BigEndian.Uint16(extensions[:2])
		extensionLen := int(binary.BigEndian.Uint16(extensions[2:4]))
		if len(extensions) < 4+extensionLen {
			return nil, io.ErrUnexpectedEOF
		}
		extensionData := extensions[4 : 4+extensionLen]
		extensions = extensions[4+extensionLen:]
		if extensionType != 51 {
			continue
		}
		// KeyShareClientHello: client_shares<0..2^16-1>
		if len(extensionData) < 2 {
			return nil, io.ErrUnexpectedEOF
		}
		sharesLen := int(binary.BigEndian.Uint16(extensionData[:2]))
		if len(extensionData) < 2+sharesLen {
			return nil, io.ErrUnexpectedEOF
		}
		shares := extensionData[2 : 2+sharesLen]
		var groups []uint16
		for len(shares) >= 4 {
			group := binary.BigEndian.Uint16(shares[:2])
			keyLen := int(binary.BigEndian.Uint16(shares[2:4]))
			if len(shares) < 4+keyLen {
				return nil, io.ErrUnexpectedEOF
			}
			shares = shares[4+keyLen:]
			groups = append(groups, group)
		}
		return groups, nil
	}
	return nil, errors.New("no key_share extension")
}

func TestRealityClientHelloCarriesMLKEMKeyShare(t *testing.T) {
	t.Parallel()

	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes())

	for _, fingerprint := range []string{"chrome", "chrome_pq"} {
		fingerprint := fingerprint
		t.Run(fingerprint, func(t *testing.T) {
			t.Parallel()

			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()

			ctx, cancel := context.WithTimeout(context.Background(), testRealityKeyShareGroupsRecordTimeout)
			defer cancel()

			handshakeErrChan := make(chan error, 1)
			go func() {
				conn, err := net.Dial("tcp", listener.Addr().String())
				if err != nil {
					handshakeErrChan <- err
					return
				}
				defer conn.Close()
				config, err := NewRealityClient(ctx,
					log.NewNOPFactory().NewLogger("reality-test"),
					"127.0.0.1:0",
					option.OutboundTLSOptions{
						Enabled:    true,
						ServerName: "www.microsoft.com",
						UTLS: &option.OutboundUTLSOptions{
							Enabled:     true,
							Fingerprint: fingerprint,
						},
						Reality: &option.OutboundRealityOptions{
							Enabled:   true,
							PublicKey: publicKey,
							ShortID:   "00c8d3",
						},
					})
				if err != nil {
					handshakeErrChan <- err
					return
				}
				compatConfig, isCompat := config.(ConfigCompat)
				if !isCompat {
					handshakeErrChan <- errors.New("reality client config is not ConfigCompat")
					return
				}
				_, err = compatConfig.ClientHandshake(ctx, conn)
				handshakeErrChan <- err
			}()

			conn, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			err = conn.SetReadDeadline(time.Now().Add(testRealityKeyShareGroupsRecordTimeout))
			if err != nil {
				t.Fatal(err)
			}
			groups, err := readClientHelloKeyShareGroups(conn)
			if err != nil {
				select {
				case handshakeErr := <-handshakeErrChan:
					if handshakeErr != nil {
						t.Fatalf("no ClientHello, handshake failed: %v", handshakeErr)
					}
				case <-time.After(testRealityKeyShareGroupsRecordTimeout):
				}
				t.Fatalf("read ClientHello key_share: %v", err)
			}
			found := false
			for _, group := range groups {
				if group == uint16(utls.X25519MLKEM768) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("ClientHello key_share groups %v lack %d (X25519MLKEM768)", groups, uint16(utls.X25519MLKEM768))
			}
		})
	}
}
