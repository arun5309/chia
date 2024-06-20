package main

import (
	"testing"
)

// Run <env vars...> go test -bench=.
func BenchmarkSimpleAggregationExample(b *testing.B) {
	for n := 0; n < b.N; n++ {
		SimpleAggregationExample()
	}
}

func BenchmarkOurProposalAugExample(b *testing.B) {
	for n := 0; n < b.N; n++ {
		OurProposalAugExample()
	}
}
