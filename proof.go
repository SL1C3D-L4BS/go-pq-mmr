package mmr

// Proof is a cryptographic inclusion proof for a single leaf in the MMR at a given position.
// It contains the leaf data and ML-DSA signature (for authenticity), the leaf hash, sibling hashes
// along the Merkle path to the leaf's peak, and other peak hashes for root bagging. Verifiers use
// Proof with the tree root and signer's public key to confirm the leaf was in the log without storing the full tree.
type Proof struct {
	Position      uint64   // 1-based leaf position in the log.
	Data          []byte   // Leaf payload; used for PQC verification and leaf hash recomputation.
	PQCSignature  []byte   // ML-DSA signature over Data for post-quantum authenticity.
	LeafHash      []byte   // Hash of the leaf (data || signature) used in the Merkle path.
	Siblings      [][]byte // Sibling hashes along the path from leaf to this leaf's peak (bottom to top).
	SiblingLeft   []bool   // SiblingLeft[i] true means the sibling was on the left (this node was right child).
	PeakHashes    [][]byte // Hashes of other peaks in left-to-right order, for root bagging.
	MyPeakIdx     int      // Index of this leaf's peak in the full peak list.
	NumPeaks      int      // Total number of peaks (1 + len(PeakHashes)).
	PeakIsLastSib bool     // When true, the peak hash is the last sibling (this leaf was left child of peak).
}
