package mmr

import "testing"

func TestPosHeight(t *testing.T) {
	// popcount(pos+1)-1: 0,1,2,3,4,5,6 -> 0,0,1,0,1,1,2; 14,29,30 -> 3,3,4
	for _, tc := range []struct {
		pos    uint64
		height uint32
	}{
		{0, 0}, {1, 0}, {2, 1}, {3, 0}, {4, 1}, {5, 1}, {6, 2},
		{14, 3}, {29, 3}, {30, 4},
	} {
		got := posHeight(tc.pos)
		if got != tc.height {
			t.Errorf("posHeight(%d) = %d, want %d", tc.pos, got, tc.height)
		}
	}
}
