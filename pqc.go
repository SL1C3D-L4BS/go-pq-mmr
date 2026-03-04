// Package mmr provides Post-Quantum Merkle Mountain Ranges for immutable, verifiable audit logs.
// This file wraps Cloudflare CIRCL's ML-DSA (Dilithium3 / FIPS 204 ML-DSA-65) for leaf-level signatures.
package mmr

import (
	"encoding"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// pqcScheme is the ML-DSA-65 (Dilithium3) scheme used for leaf signatures.
var pqcScheme sign.Scheme = mldsa65.Scheme()

// GeneratePQCKeys generates a new ML-DSA (FIPS 204 ML-DSA-65) key pair.
// Keys are returned as raw bytes suitable for storage or passing to SignPQC and VerifyPQC.
// Use these keys to sign leaves in the MMR for post-quantum authenticity; the public key is shared with verifiers.
func GeneratePQCKeys() (publicKey []byte, privateKey []byte, err error) {
	pk, sk, err := pqcScheme.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	pubBytes, _ := pk.(encoding.BinaryMarshaler).MarshalBinary()
	privBytes, _ := sk.(encoding.BinaryMarshaler).MarshalBinary()
	return pubBytes, privBytes, nil
}

// SignPQC signs message with the given ML-DSA private key (raw bytes from GeneratePQCKeys).
// Use this when appending signed leaves via Tree.AppendSigned; the signature provides post-quantum authenticity for the leaf data.
func SignPQC(privateKey, message []byte) (signature []byte, err error) {
	sk, err := pqcScheme.UnmarshalBinaryPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	sig := pqcScheme.Sign(sk, message, nil)
	return sig, nil
}

// VerifyPQC verifies an ML-DSA signature on message with the given public key (raw bytes from GeneratePQCKeys).
// Used during proof verification to ensure the leaf data was signed by the holder of the private key; safe against quantum adversaries.
func VerifyPQC(publicKey, message, signature []byte) bool {
	pk, err := pqcScheme.UnmarshalBinaryPublicKey(publicKey)
	if err != nil {
		return false
	}
	return pqcScheme.Verify(pk, message, signature, nil)
}
