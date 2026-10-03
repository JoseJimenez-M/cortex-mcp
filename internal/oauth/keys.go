package oauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
)

// signingKey signs the ID token the library mints at every code exchange.
// Nothing here reads ID tokens; the key exists because the library always
// issues one (spec 6.2). ES256 keeps the key small and the code stdlib-only.
type signingKey struct {
	kid  string
	priv *ecdsa.PrivateKey
}

func (k signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.ES256 }
func (k signingKey) Key() any                                    { return k.priv }
func (k signingKey) ID() string                                  { return k.kid }

// publicKey is the signing key as published on /keys.
type publicKey struct {
	kid string
	pub *ecdsa.PublicKey
}

func (k publicKey) ID() string                         { return k.kid }
func (k publicKey) Algorithm() jose.SignatureAlgorithm { return jose.ES256 }
func (k publicKey) Use() string                        { return "sig" }
func (k publicKey) Key() any                           { return k.pub }

// loadKeys returns the signing key and the AES-256 key (with its id) that
// encrypts opaque access tokens and codes, creating both on first use. They
// live in auth.db, outside the vault, and survive reset-auth, which deletes
// every token instead.
func (s *Store) loadKeys() (signingKey, [32]byte, string, error) {
	var sk signingKey
	var ck [32]byte
	var ckid string
	err := s.tx(func(tx *sql.Tx) error {
		kid, material, err := loadKey(tx, "signing", func() ([]byte, error) {
			priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return nil, err
			}
			return x509.MarshalPKCS8PrivateKey(priv)
		})
		if err != nil {
			return err
		}
		parsed, err := x509.ParsePKCS8PrivateKey(material)
		if err != nil {
			return err
		}
		priv, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return errors.New("stored signing key is not ECDSA")
		}
		sk = signingKey{kid: kid, priv: priv}
		ckid, material, err = loadKey(tx, "crypto", func() ([]byte, error) { return randBytes(32), nil })
		if err != nil {
			return err
		}
		if len(material) != len(ck) {
			return fmt.Errorf("stored crypto key has %d bytes, want %d", len(material), len(ck))
		}
		copy(ck[:], material)
		return nil
	})
	return sk, ck, ckid, err
}

func loadKey(tx *sql.Tx, name string, gen func() ([]byte, error)) (string, []byte, error) {
	var kid string
	var material []byte
	err := tx.QueryRow(`SELECT kid, material FROM oauth_keys WHERE name = ?`, name).Scan(&kid, &material)
	if err == nil {
		return kid, material, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", nil, err
	}
	if material, err = gen(); err != nil {
		return "", nil, err
	}
	kid = rand.Text()
	_, err = tx.Exec(`INSERT INTO oauth_keys(name, kid, material) VALUES(?, ?, ?)`, name, kid, material)
	return kid, material, err
}
