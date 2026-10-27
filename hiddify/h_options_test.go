package hiddify

import "testing"

// Both ends of a range are reachable: a count of 1-3 sometimes sends 3.
func TestH_RandBetweenInclusive(t *testing.T) {
	seen := map[int64]bool{}
	for range 2000 {
		value := RandBetween(1, 3)
		if value < 1 || value > 3 {
			t.Fatalf("out of range: %d", value)
		}
		seen[value] = true
	}
	if len(seen) != 3 {
		t.Fatalf("not every value was drawn: %v", seen)
	}
	if value := RandBetween(5, 5); value != 5 {
		t.Fatalf("RandBetween(5, 5) = %d", value)
	}
}
