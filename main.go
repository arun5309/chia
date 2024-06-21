package main

import (
	"crypto/rand"
	"fmt"
	"github.com/dashpay/bls-signatures/go-bindings" // Module blschia (make sure to compile it and have its path in the environment variables CGO_CXXFLAGS and CGO_LDFLAGS. blschia also has interesting benchmarks but its for the c++ version)
)

/*
	Example compile command:

	CGO_CXXFLAGS=" -I/home/arun/Documents/IISc/projects/npci/aggregate_signatures/bls-signatures/go-bindings/../build/depends/relic/include -I/home/arun/Documents/IISc/projects/npci/aggregate_signatures/bls-signatures/go-bindings/../depends/mimalloc/include -I/home/arun/Documents/IISc/projects/npci/aggregate_signatures/bls-signatures/go-bindings/../depends/relic/include -I/home/arun/Documents/IISc/projects/npci/aggregate_signatures/bls-signatures/go-bindings/../include" CGO_LDFLAGS=" -L/home/arun/Documents/IISc/projects/npci/aggregate_signatures/bls-signatures/go-bindings/../build/depends/mimalloc -L/home/arun/Documents/IISc/projects/npci/aggregate_signatures/bls-signatures/go-bindings/../build/depends/relic/lib -L/home/arun/Documents/IISc/projects/npci/aggregate_signatures/bls-signatures/go-bindings/../build/src -ldashbls -lrelic_s -lmimalloc-secure -lgmp" go build
*/

// TODO: Explore different signature schemes like BasicSchemeMPL, AugSchemeMPL, PopSchemeMPL
// TODO: Explore batching: say endorsing multiple transactions at a time with a single signature (this might complicate how transactions are allocated to a block and could potentially introduce starvation issues if not handled properly) but will have huge computation and communication wins provided batch size is high (figuring out the correct size is crucial)
// TODO: Batching keys ahead of time might improve performance even further but we might need to batch (could pre-compute or at least maintain a pool of some pre-computed values (caching)) exponential (in the number of signers (i.e endorsers, orderers, etc.)) number of configuration policies. We might get away with pre-computing for only small subsets of signers.
// TODO: Make benchmarks more representative and compare against status quo

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

func makeRandomArray(n int) ([]byte, error) {
	token := make([]byte, n)
	_, err := rand.Read(token)
	return token, err
}

func OurProposalAugExample() {
	// Key generation (one time only needed during setup)
	npci_seed, _ := makeRandomArray(32)
	rbi_seed, _ := makeRandomArray(32)
	sbi_seed, _ := makeRandomArray(32)
	hdfc_seed, _ := makeRandomArray(32)
	orderer_seed, _ := makeRandomArray(32)

	scheme := blschia.NewAugSchemeMPL()

	npci_sk, _ := scheme.KeyGen(npci_seed)
	rbi_sk, _ := scheme.KeyGen(rbi_seed)
	sbi_sk, _ := scheme.KeyGen(sbi_seed)
	hdfc_sk, _ := scheme.KeyGen(hdfc_seed)
	orderer_sk, _ := scheme.KeyGen(orderer_seed)

	// The public keys can be distributed using the public key infrastructure
	npci_pk, _ := npci_sk.G1Element()
	rbi_pk, _ := rbi_sk.G1Element()
	sbi_pk, _ := sbi_sk.G1Element()
	hdfc_pk, _ := hdfc_sk.G1Element()
	orderer_pk, _ := orderer_sk.G1Element()

	// Creating fake transaction proposals (Assuming payload size is about 5000 bytes).
	// Here, proposal is assumed to contain the configuration policy as well.
	// For the sake of simplicity we assume things like endorsers/orderer doesn't add any data (does not include signatures and stuff like that) to the proposal'
	proposal1, _ := makeRandomArray(5000) // Say for SBI to HDFC transfer
	// SBI client sends proposal1 to other endorsers i.e NPCI, RBI, (SBI), HDFC

	proposal2, _ := makeRandomArray(5000) // Say for HDFC to SBI transfer
	// HDFC client sends proposal2 to other endorsers i.e NPCI, RBI, SBI, (HDFC)

	// Creating endorsements for proposals
	proposal1_npci_endorsement := scheme.Sign(npci_sk, proposal1)
	proposal1_rbi_endorsement := scheme.Sign(rbi_sk, proposal1)
	proposal1_sbi_endorsement := scheme.Sign(sbi_sk, proposal1)
	proposal1_hdfc_endorsement := scheme.Sign(hdfc_sk, proposal1)
	// SBI client receives endorsements from endorsers (implied that endorsers need to send this to the originating client)

	proposal2_npci_endorsement := scheme.Sign(npci_sk, proposal2)
	proposal2_rbi_endorsement := scheme.Sign(rbi_sk, proposal2)
	proposal2_sbi_endorsement := scheme.Sign(sbi_sk, proposal2)
	proposal2_hdfc_endorsement := scheme.Sign(hdfc_sk, proposal2)
	// HDFC client receives endorsements from endorsers (implied that endorsers need to send this to the originating client)

	// Aggregating endorsements to obtain transaction payload by the client but the client needs to verify endorsements. Assume, that aggregation ordering always follows some convention like a fixed ordering
	transaction1_agg_sign := scheme.AggregateSigs(proposal1_npci_endorsement, proposal1_rbi_endorsement, proposal1_sbi_endorsement, proposal1_hdfc_endorsement)
	ok := scheme.AggregateVerify([]*blschia.G1Element{npci_pk, rbi_pk, sbi_pk, hdfc_pk}, [][]byte{proposal1, proposal1, proposal1, proposal1}, transaction1_agg_sign)
	if !ok {
		// When verifying aggregate fails do below (this is cold path):
		ok = scheme.Verify(npci_pk, proposal1, proposal1_npci_endorsement)
		if !ok {
			panic("NPCI endorsement failed")
		}
		ok = scheme.Verify(rbi_pk, proposal1, proposal1_rbi_endorsement)
		if !ok {
			panic("RBI endorsement failed")
		}
		ok = scheme.Verify(sbi_pk, proposal1, proposal1_sbi_endorsement)
		if !ok {
			panic("SBI endorsement failed")
		}
		ok = scheme.Verify(hdfc_pk, proposal1, proposal1_hdfc_endorsement)
		if !ok {
			panic("HDFC endorsement failed")
		}
	}
	// SBI client sends transaction (proposal1 here for simplicity) and the aggregate signature of endorsements to the orderer

	transaction2_agg_sign := scheme.AggregateSigs(proposal2_npci_endorsement, proposal2_rbi_endorsement, proposal2_sbi_endorsement, proposal2_hdfc_endorsement)
	ok = scheme.AggregateVerify([]*blschia.G1Element{npci_pk, rbi_pk, sbi_pk, hdfc_pk}, [][]byte{proposal2, proposal2, proposal2, proposal2}, transaction2_agg_sign)
	if !ok {
		// When verifying aggregate fails do below (this is cold path):
		ok = scheme.Verify(npci_pk, proposal2, proposal2_npci_endorsement)
		if !ok {
			panic("NPCI endorsement failed")
		}
		ok = scheme.Verify(rbi_pk, proposal2, proposal2_rbi_endorsement)
		if !ok {
			panic("RBI endorsement failed")
		}
		ok = scheme.Verify(sbi_pk, proposal2, proposal2_sbi_endorsement)
		if !ok {
			panic("SBI endorsement failed")
		}
		ok = scheme.Verify(hdfc_pk, proposal2, proposal2_hdfc_endorsement)
		if !ok {
			panic("HDFC endorsement failed")
		}
	}
	// HDFC client sends transaction (proposal2 here for simplicity) and the aggregate signature of endorsements to the orderer

	// The orderer combines multiple transactions into a block (need to optimize this number incorporating this proposal).
	// Two transactions per block is taken here for simplicity.
	// Orderer needs to verify the aggregated signatures though.
	// It verifies immediately as can't afford to wait for a block to fill up with transactions (check?); that is why we don't verify the block signature first

	ok = scheme.AggregateVerify([]*blschia.G1Element{npci_pk, rbi_pk, sbi_pk, hdfc_pk}, [][]byte{proposal1, proposal1, proposal1, proposal1}, transaction1_agg_sign)
	if !ok {
		panic("SBI client has sent an invalid transaction")
	}

	ok = scheme.AggregateVerify([]*blschia.G1Element{npci_pk, rbi_pk, sbi_pk, hdfc_pk}, [][]byte{proposal2, proposal2, proposal2, proposal2}, transaction2_agg_sign)
	if !ok {
		panic("HDFC client has sent an invalid transaction")
	}

	block_payload := append(proposal1, proposal2...)
	block_orderer_sign := scheme.Sign(orderer_sk, block_payload)
	block_sign := scheme.AggregateSigs(transaction1_agg_sign, transaction2_agg_sign, block_orderer_sign)
	// The orderer sends block_payload and block_sign to peers for committing

	// Peer verification (needs to be run by each peer).
	txn1_payload := block_payload[:5000]
	txn2_payload := block_payload[5000:]
	// Check for ordering effects in below for performance in hot and cold paths (it probably doesn't make a big difference)'
	ok = scheme.AggregateVerify([]*blschia.G1Element{orderer_pk, npci_pk, rbi_pk, sbi_pk, hdfc_pk, npci_pk, rbi_pk, sbi_pk, hdfc_pk}, [][]byte{block_payload, txn1_payload, txn1_payload, txn1_payload, txn1_payload, txn2_payload, txn2_payload, txn2_payload, txn2_payload}, block_sign)

	// Observations:
	// At most having one signature per step or message thereby reducing communication (bandwidth)
	// No nested signing. That we are signing another signature (ignoring signatures due mTLS). This reduces message size for signatures thereby reducing computation time.
	// All verifications are comprehensive i.e aggregation has the same verification capabilities as sending individual signatures
	// Observe that aggregation doesn't need know to know about any parameters. This even applies to hierarchical (i.e. multi-level) aggregation.
}

func Scratch() {
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

	fmt.Println("Seed: ", seed)
	ser := aggSig.Serialize()
	fmt.Println("Aggregate signature: ", ser)
	deser, _ := blschia.G2ElementFromBytes(ser)
	fmt.Println("Deserialized: ", deser)
	fmt.Println("Merged: ", append(msg1, msg2[:]...))
	fmt.Println("pk size: ", len(pk1.Serialize()))
	fmt.Println("sk size: ", len(sk1.Serialize()))
	fmt.Println("sign size: ", len(sig1.Serialize()))
	fmt.Println("Agg sign size: ", len(aggSig.Serialize()))
	token := make([]byte, 4)
	fmt.Println("Unrandomized token:", token)
	rand.Read(token)
	fmt.Println("Randomized token:", token)

	ok := scheme.AggregateVerify([]*blschia.G1Element{pk1, pk2}, [][]byte{msg1, msg2}, aggSig)
	if !ok {
		panic("failed a verification of the aggregated signature ")
	}
}

func main() {
	fmt.Println("Starting aggregate signatures benchmark!")
	Scratch()
	OurProposalAugExample()
	fmt.Println("Finishing aggregate signatures benchmark!")
}
