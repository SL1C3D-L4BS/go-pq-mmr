package mmr

import (
	"crypto/sha256"
)

// hashNode concatenates left and right and returns SHA-256(left || right).
func hashNode(left, right []byte) []byte {
	h := sha256.New()
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// hashLeaf hashes the leaf data and PQC signature together: SHA-256(data || signature).
func hashLeaf(data, signature []byte) []byte {
	h := sha256.New()
	h.Write(data)
	h.Write(signature)
	return h.Sum(nil)
}
