package key_manager

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

// encryptDEKWithECCPublicKey encrypts plaintext using ECIES with the provided ECDSA public key.
// The output format is: ephemeralPublicX || ephemeralPublicY || nonce || ciphertext
func encryptDEKWithECCPublicKey(publicKey *ecdsa.PublicKey, plaintext []byte) ([]byte, error) {
	if publicKey == nil || publicKey.Curve == nil {
		return nil, fmt.Errorf("invalid ECC public key")
	}

	peer, err := publicKey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("invalid ECC public key: %w", err)
	}
	ephemeralKey, err := peer.Curve().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}
	encKey, err := eccDEKKey(ephemeralKey, peer)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Wire format: ephemeral X || Y (fixed-size coordinates) || nonce || ciphertext.
	ephemeralPoint := ephemeralKey.PublicKey().Bytes() // 0x04 || X || Y
	out := make([]byte, 0, len(ephemeralPoint)-1+len(ciphertext))
	out = append(out, ephemeralPoint[1:]...)
	out = append(out, ciphertext...)
	return out, nil
}

// decryptDEKWithECCPrivateKey decrypts ECIES ciphertext produced by encryptDEKWithECCPublicKey.
func decryptDEKWithECCPrivateKey(privateKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	if privateKey == nil || privateKey.Curve == nil {
		return nil, fmt.Errorf("invalid ECC private key")
	}

	coordSize := (privateKey.Curve.Params().BitSize + 7) / 8
	headerSize := coordSize * 2
	if len(data) <= headerSize {
		return nil, fmt.Errorf("ciphertext too short for ECC payload")
	}

	ciphertext := data[headerSize:]

	priv, err := privateKey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("invalid ECC private key: %w", err)
	}
	ephemeralPub, err := priv.Curve().NewPublicKey(append([]byte{0x04}, data[:headerSize]...))
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral public key: %w", err)
	}
	encKey, err := eccDEKKey(priv, ephemeralPub)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext missing nonce")
	}

	nonce := ciphertext[:nonceSize]
	payload := ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, payload, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt payload: %w", err)
	}
	return plaintext, nil
}

// eccDEKKey derives the AES-256 key for an ECC-wrapped DEK: ECDH through
// crypto/ecdh (the FIPS 140-3 approved service, which validates the peer and
// returns the fixed-length shared secret SP 800-56A requires), then HKDF-SHA256.
// Clients (e.g. the browser SDK) derive the same key from the same inputs.
func eccDEKKey(priv *ecdh.PrivateKey, peer *ecdh.PublicKey) ([]byte, error) {
	sharedSecret, err := priv.ECDH(peer)
	if err != nil {
		return nil, fmt.Errorf("failed to derive shared secret: %w", err)
	}
	encKey, err := hkdf.Key(sha256.New, sharedSecret, nil, "key-manager-ecc-dek", 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive encryption key: %w", err)
	}
	return encKey, nil
}
