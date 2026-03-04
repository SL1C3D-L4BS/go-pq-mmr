package mmr

import "math/bits"

// posHeight returns the height of the node at the given 0-based MMR position.
// Height 0 = leaf. Formula: popcount(pos+1) - 1 (so node at 2 has height 1, etc.).
func posHeight(pos uint64) uint32 {
	n := pos + 1
	ones := uint32(bits.OnesCount64(n))
	if ones <= 1 {
		return 0
	}
	return ones - 1
}

// bign returns the smallest number >= n that is of the form 2^k - 1.
func bign(n uint64) uint64 {
	if n == 0 {
		return 0
	}
	k := 64 - bits.LeadingZeros64(n)
	return (uint64(1) << k) - 1
}

// peaks returns the 0-based MMR positions of all current peaks for the given leaf count.
// Peaks are ordered from left to right (largest position first in the slice).
// For bagging we iterate right-to-left (smallest to largest position).
func peaks(size uint64) []uint64 {
	if size == 0 {
		return nil
	}
	var result []uint64
	offset := uint64(0)
	s := size
	for s > 0 {
		// largest power of 2 <= s
		k := uint64(1) << (63 - bits.LeadingZeros64(s))
		numNodes := 2*k - 1
		peakPos := offset + numNodes - 1
		result = append(result, peakPos)
		offset += numNodes
		s -= k
	}
	return result
}

// leafPos returns the 0-based MMR position of the (n+1)-th leaf (n is 0-based leaf index).
// leafPos(k) = 2*k - popcount(k).
func leafPos(leafIndex uint64) uint64 {
	return (leafIndex << 1) - uint64(bits.OnesCount64(leafIndex))
}

