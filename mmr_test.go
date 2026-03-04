package mmr

import (
	"crypto/rand"
	"testing"
)

func TestNewTree(t *testing.T) {
	tree := NewTree()
	if tree == nil || tree.leaves == nil {
		t.Fatal("NewTree should return initialized tree")
	}
	if tree.Root() != nil {
		t.Error("empty tree root should be nil")
	}
}

func TestAppendSignedAndProof(t *testing.T) {
	tree := NewTree()
	pub, priv, _ := GeneratePQCKeys()
	position, err := tree.AppendSigned([]byte("data"), priv)
	if err != nil {
		t.Fatal(err)
	}
	if position != 1 {
		t.Errorf("first position should be 1, got %d", position)
	}
	proof, err := tree.GenerateProof(position)
	if err != nil {
		t.Fatal(err)
	}
	if proof == nil || proof.Position != position {
		t.Error("proof should match position")
	}
	root := tree.Root()
	if len(root) != 32 {
		t.Errorf("root should be 32 bytes, got %d", len(root))
	}
	ok := tree.VerifyProof(proof, pub, root)
	if !ok {
		t.Error("VerifyProof should succeed for valid proof")
	}
}

func Test100LeavesProof42(t *testing.T) {
	tree := NewTree()
	pub, priv, err := GeneratePQCKeys()
	if err != nil {
		t.Fatal(err)
	}
	const numLeaves = 100
	for i := 0; i < numLeaves; i++ {
		data := make([]byte, 32)
		rand.Read(data)
		_, err := tree.AppendSigned(data, priv)
		if err != nil {
			t.Fatal(err)
		}
	}
	if tree.size != numLeaves {
		t.Fatalf("expected %d leaves, got %d", numLeaves, tree.size)
	}
	root := tree.Root()
	if len(root) != 32 {
		t.Fatalf("root should be 32 bytes, got %d", len(root))
	}
	proofPos := uint64(42)
	proof, err := tree.GenerateProof(proofPos)
	if err != nil {
		t.Fatal(err)
	}
	if proof == nil {
		t.Fatalf("proof for position %d should not be nil", proofPos)
	}
	if proof.Position != proofPos {
		t.Errorf("proof position should be %d, got %d", proofPos, proof.Position)
	}
	ok := tree.VerifyProof(proof, pub, root)
	if !ok {
		if !VerifyPQC(pub, proof.Data, proof.PQCSignature) {
			t.Error("PQC verification failed")
		}
		t.Errorf("VerifyProof should succeed for leaf #%d", proofPos)
	}
	// Verify wrong root fails
	ok = tree.VerifyProof(proof, pub, make([]byte, 32))
	if ok {
		t.Error("VerifyProof should fail for wrong root")
	}
}
