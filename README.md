# 🏔️ go-pq-mmr

**Post-Quantum Merkle Mountain Ranges for Go.**

[![Go Reference](https://pkg.go.dev/badge/github.com/vericore/go-pq-mmr.svg)](https://pkg.go.dev/github.com/vericore/go-pq-mmr)
[![NIST Post-Quantum](https://img.shields.io/badge/Cryptography-FIPS%20204%20ML--DSA-blue)](https://csrc.nist.gov/projects/post-quantum-cryptography)

`go-pq-mmr` is a lightning-fast, highly optimized Merkle Mountain Range (MMR) implementation in Go, strictly designed for immutable audit logs and AI compliance.

Unlike standard Merkle Trees, MMRs are append-only. This makes them significantly faster for continuous logging (O(1) appends). To ensure long-term legal and cryptographic validity, every leaf is optionally signed using **NIST FIPS 204 ML-DSA (formerly Dilithium3)** via Cloudflare CIRCL, making your ledger mathematically immune to quantum computing attacks.

## 📦 Installation

```bash
go get github.com/vericore/go-pq-mmr
```

## ⚡ Quickstart

```go
package main

import (
	"fmt"
	"github.com/vericore/go-pq-mmr"
)

func main() {
	// 1. Initialize an in-memory or disk-backed MMR
	tree := mmr.NewTree()

	// 2. Generate an ephemeral Post-Quantum Keypair (ML-DSA)
	pubKey, privKey, _ := mmr.GeneratePQCKeys()

	// 3. Append data to the tree
	auditLog := []byte(`{"agent": "treasury_01", "intent": "wire_funds"}`)
	position, _ := tree.AppendSigned(auditLog, privKey)

	// 4. Generate a cryptographic proof of inclusion
	proof, _ := tree.GenerateProof(position)

	// 5. Verify the proof against the quantum signature and the Tree Root
	isValid := tree.VerifyProof(proof, pubKey, tree.Root())
	fmt.Printf("Log verified: %v\n", isValid)
}
```

## 🧠 Why MMR over standard Merkle Trees?

Standard Merkle trees require you to re-hash the entire tree when new data is added. An MMR is a collection of perfectly balanced Merkle trees. When you append a new leaf, you only hash the new peaks, making it exceptionally efficient for massive, append-only datasets like AI flight recorders or blockchain state.
