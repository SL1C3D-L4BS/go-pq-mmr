// Package mmr provides Post-Quantum Merkle Mountain Ranges for immutable audit logs.
package mmr

import "bytes"

// Leaf represents a single leaf in the Merkle Mountain Range.
// It holds the application payload, an optional post-quantum (ML-DSA) signature over that data,
// and the leaf hash used for Merkle verification. This structure enables both authenticity
// (via PQC signature) and inclusion proofs (via the hash in the tree).
type Leaf struct {
	Data         []byte // Raw payload; the application data stored at this leaf.
	PQCSignature []byte // Optional ML-DSA signature over Data for post-quantum authenticity.
	Hash         []byte // Hash of (Data || PQCSignature) used in the MMR structure.
}

// Tree is an in-memory Merkle Mountain Range index supporting append-only, verifiable audit logs.
// It maintains leaves (1-based user positions), internal node hashes (0-based MMR positions),
// and heights for merge logic. The MMR structure provides O(log n) append and compact inclusion
// proofs, making it efficient for high-throughput, post-quantum secure logging.
type Tree struct {
	leaves  map[uint64]*Leaf
	nodes   map[uint64][]byte // 0-based MMR position -> hash (leaves and internal)
	heights map[uint64]uint32  // 0-based MMR position -> height (0 = leaf)
	size    uint64
}

// NewTree creates a new empty in-memory MMR tree.
// Use it to build an append-only log where each leaf can be signed with ML-DSA and later proven with inclusion proofs.
func NewTree() *Tree {
	return &Tree{
		leaves:  make(map[uint64]*Leaf),
		nodes:  make(map[uint64][]byte),
		heights: make(map[uint64]uint32),
		size:   0,
	}
}

// Root returns the current MMR root by bagging all peaks from right to left.
// The root commits to the entire tree state; verifiers use it to check that a Proof matches the expected log.
func (t *Tree) Root() []byte {
	if t.size == 0 {
		return nil
	}
	peakPositions := peaks(t.size)
	if len(peakPositions) == 0 {
		return nil
	}
	// Bag from right to left: smallest position first
	bag := t.nodes[peakPositions[len(peakPositions)-1]]
	for i := len(peakPositions) - 2; i >= 0; i-- {
		bag = hashNode(bag, t.nodes[peakPositions[i]])
	}
	return bag
}

// AppendSigned adds a new leaf to the Merkle Mountain Range, signing the data with the provided ML-DSA private key.
// It returns the 1-based leaf position. This is the primary append path for post-quantum secure, append-only logs:
// each entry is authenticated and can later be proven with GenerateProof and verified with VerifyProof.
func (t *Tree) AppendSigned(data, privateKey []byte) (position uint64, err error) {
	sig, err := SignPQC(privateKey, data)
	if err != nil {
		return 0, err
	}
	leafHash := hashLeaf(data, sig)
	position = t.size + 1
	leafIndex := t.size
	pos := leafPos(leafIndex)

	t.leaves[position] = &Leaf{
		Data:         data,
		PQCSignature: sig,
		Hash:         leafHash,
	}
	t.nodes[pos] = leafHash
	t.heights[pos] = 0

	// Merge while we have a left sibling at the same height (at pos - (2^(h+1)-1)).
	for {
		height := t.heights[pos]
		if pos == 0 {
			break
		}
		leftSibOffset := uint64((1 << (height + 1)) - 1)
		if pos < leftSibOffset {
			break
		}
		prevPos := pos - leftSibOffset
		if t.heights[prevPos] != height {
			break
		}
		parentPos := pos + 1
		leftHash := t.nodes[prevPos]
		rightHash := t.nodes[pos]
		parentHash := hashNode(leftHash, rightHash)
		t.nodes[parentPos] = parentHash
		t.heights[parentPos] = height + 1
		pos = parentPos
	}

	t.size++
	return position, nil
}

// leafToMMRPos returns the 0-based MMR position for a 1-based user position.
func (t *Tree) leafToMMRPos(userPos uint64) uint64 {
	if userPos == 0 || userPos > t.size {
		return 0
	}
	return leafPos(userPos - 1)
}

// GenerateProof builds an inclusion proof for the leaf at the given 1-based position.
// The proof allows a verifier with the tree root and the signer's public key to confirm that the leaf
// was in the tree at that position, without needing the full log—efficient for distribution and audit.
func (t *Tree) GenerateProof(position uint64) (*Proof, error) {
	leaf, ok := t.leaves[position]
	if !ok {
		return nil, nil
	}
	mmrPos := t.leafToMMRPos(position)
	peakPositions := peaks(t.size)

	// Find which peak this leaf belongs to (first peak that is >= mmrPos).
	var myPeakIdx int
	for i, p := range peakPositions {
		if p >= mmrPos {
			myPeakIdx = i
			break
		}
	}
	myPeakPos := peakPositions[myPeakIdx]

	// Collect Merkle path (sibling hashes) from mmrPos up to myPeakPos.
	var siblings [][]byte
	var siblingLeft []bool
	curPos := mmrPos
	const maxPathLen = 64
	for step := 0; curPos != myPeakPos && step < maxPathLen; step++ {
		h := t.heights[curPos]
		var siblingPos uint64
		var parentPos uint64
		// We're the right child iff the node at (curPos-1) has the same height (it's our left sibling).
		isRightChild := curPos > 0 && t.heights[curPos-1] == h
		if isRightChild {
			siblingPos = curPos - 1
			parentPos = curPos + 1
		} else {
			siblingPos = curPos + 1
			parentPos = siblingPos + 1
		}
		if sib, ok := t.nodes[siblingPos]; ok {
			siblings = append(siblings, sib)
			siblingLeft = append(siblingLeft, isRightChild)
		}
		curPos = parentPos
		if curPos > myPeakPos {
			// We're the left child of the peak; the sibling we just added is the peak hash.
			return &Proof{
				Position:        position,
				Data:            leaf.Data,
				PQCSignature:    leaf.PQCSignature,
				LeafHash:        leaf.Hash,
				Siblings:        siblings,
				SiblingLeft:     siblingLeft,
				PeakHashes:      collectOtherPeakHashes(t, peakPositions, myPeakIdx),
				MyPeakIdx:       myPeakIdx,
				NumPeaks:        len(peakPositions),
				PeakIsLastSib:   true,
			}, nil
		}
	}

	// Other peak hashes (for bagging): all peaks except the one we computed, in peak order.
	otherPeakHashes := collectOtherPeakHashes(t, peakPositions, myPeakIdx)
	return &Proof{
		Position:     position,
		Data:         leaf.Data,
		PQCSignature: leaf.PQCSignature,
		LeafHash:     leaf.Hash,
		Siblings:     siblings,
		SiblingLeft:  siblingLeft,
		PeakHashes:   otherPeakHashes,
		MyPeakIdx:    myPeakIdx,
		NumPeaks:     len(peakPositions),
	}, nil
}

func collectOtherPeakHashes(t *Tree, peakPositions []uint64, myPeakIdx int) [][]byte {
	other := make([][]byte, 0, len(peakPositions)-1)
	for i, p := range peakPositions {
		if i == myPeakIdx {
			continue
		}
		if h := t.nodes[p]; len(h) > 0 {
			other = append(other, h)
		}
	}
	return other
}

// VerifyProof checks an inclusion proof against the signer's public key and the expected MMR root.
// It validates both the ML-DSA signature on the leaf data and the Merkle path, ensuring the leaf
// was part of the committed log. Returns true only if both post-quantum signature and inclusion check pass.
func (t *Tree) VerifyProof(proof *Proof, publicKey, expectedRoot []byte) bool {
	if proof == nil || len(expectedRoot) == 0 {
		return false
	}
	if !VerifyPQC(publicKey, proof.Data, proof.PQCSignature) {
		return false
	}
	leafHash := hashLeaf(proof.Data, proof.PQCSignature)
	curHash := leafHash
	for i, sib := range proof.Siblings {
		if i < len(proof.SiblingLeft) && proof.SiblingLeft[i] {
			curHash = hashNode(sib, curHash)
		} else {
			curHash = hashNode(curHash, sib)
		}
	}
	if proof.PeakIsLastSib && len(proof.Siblings) > 0 {
		curHash = proof.Siblings[len(proof.Siblings)-1]
	}
	// Reconstruct ordered peak hashes (same order as peaks(): left to right) and bag (rightmost first).
	allPeaks := make([][]byte, proof.NumPeaks)
	allPeaks[proof.MyPeakIdx] = curHash
	j := 0
	for i := 0; i < proof.NumPeaks && j < len(proof.PeakHashes); i++ {
		if i != proof.MyPeakIdx {
			allPeaks[i] = proof.PeakHashes[j]
			j++
		}
	}
	bag := allPeaks[proof.NumPeaks-1]
	for i := proof.NumPeaks - 2; i >= 0; i-- {
		bag = hashNode(bag, allPeaks[i])
	}
	return bytes.Equal(bag, expectedRoot)
}
