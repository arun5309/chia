package main

import (
	"fmt"
	"github.com/dashpay/bls-signatures/go-bindings" // Module blschia (make sure to compile it and have its path in the environment variables CGO_CXXFLAGS and CGO_LDFLAGS. blschia also has interesting benchmarks but its for the c++ version)
)

/*
	Example compile command:

	CGO_CXXFLAGS=" -I/home/arun/Documents/IISc/projects/npci/aggregate_signatures/bls-signatures/go-bindings/../build/depends/relic/include -I/home/arun/Documents/IISc/projects/npci/aggregate_signatures/bls-signatures/go-bindings/../depends/mimalloc/include -I/home/arun/Documents/IISc/projects/npci/aggregate_signatures/bls-signatures/go-bindings/../depends/relic/include -I/home/arun/Documents/IISc/projects/npci/aggregate_signatures/bls-signatures/go-bindings/../include" CGO_LDFLAGS=" -L/home/arun/Documents/IISc/projects/npci/aggregate_signatures/bls-signatures/go-bindings/../build/depends/mimalloc -L/home/arun/Documents/IISc/projects/npci/aggregate_signatures/bls-signatures/go-bindings/../build/depends/relic/lib -L/home/arun/Documents/IISc/projects/npci/aggregate_signatures/bls-signatures/go-bindings/../build/src -ldashbls -lrelic_s -lmimalloc-secure -lgmp" go build
*/

func SimpleAggregationExample() {
	seed := []byte{
		0, 50, 6, 244, 24, 199, 1, 25,
		52, 88, 192, 19, 18, 12, 89, 6,
		220, 18, 102, 58, 209, 82, 12, 62,
		89, 110, 182, 9, 44, 20, 254, 22,
	}
	scheme := blschia.NewAugSchemeMPL()
	seed[0] = 1
	// Ignored error checking using '_'
	sk1, _ := scheme.KeyGen(seed)
	seed[0] = 2
	sk2, _ := scheme.KeyGen(seed)
	msg1 := []byte{1, 2, 3, 4, 5}
	msg2 := []byte{1, 2, 3, 4, 5, 6, 7}

	// Generate first sig
	pk1, _ := sk1.G1Element()
	sig1 := scheme.Sign(sk1, msg1)

	// Generate second sig
	pk2, _ := sk2.G1Element()
	sig2 := scheme.Sign(sk2, msg2)

	// Signatures can be non-interactively combined by anyone
	var aggSig = scheme.AggregateSigs(sig1, sig2)

	ok := scheme.AggregateVerify([]*blschia.G1Element{pk1, pk2}, [][]byte{msg1, msg2}, aggSig)
	if !ok {
		panic("failed a verification of the aggregated signature ")
	}
}

func main() {
	fmt.Println("Starting aggregate signatures benchmark!")
	SimpleAggregationExample()
	fmt.Println("Finishing aggregate signatures benchmark!")
}
