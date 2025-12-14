package unit_test

import (
	"context"
	"math/big"
	"testing"

	x402 "x402-go"
	"x402-go/mechanisms/evm"
	evmclient "x402-go/mechanisms/evm/exact/client"
	evmfacilitator "x402-go/mechanisms/evm/exact/facilitator"
	"x402-go/types"
)

// TestEVMVerifyAndSettle tests the Verify and Settle logic with mocks
func TestEVMVerifyAndSettle(t *testing.T) {
	ctx := context.Background()

	// Setup client
	// Address corresponds to hardcoded private key in mockClientEvmSigner
	expectedAddress := "0x14791697260E4c9A71f18484C9f997B308e59325"
	clientSigner := &mockClientEvmSigner{
		address: expectedAddress,
	}
	client := x402.Newx402Client()
	evmClient := evmclient.NewExactEvmScheme(clientSigner)
	client.Register("eip155:8453", evmClient)

	// Setup facilitator
	facilitatorSigner := newMockFacilitatorEvmSigner()
	// Populate balance for client
	facilitatorSigner.balances[expectedAddress+":0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"] = big.NewInt(2000000)

	config := &evmfacilitator.ExactEvmSchemeConfig{}
	evmFacilitator := evmfacilitator.NewExactEvmScheme(facilitatorSigner, config)

	// Create payment requirement
	req := types.PaymentRequirements{
		Scheme:  evm.SchemeExact,
		Network: "eip155:8453",
		Asset:   "erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", // USDC on Base
		Amount:  "1000000",                                          // 1 USDC
		PayTo:   "0xabcdef1234567890123456789012345678901234",
	}

	// Create payload
	payload, err := client.CreatePaymentPayload(ctx, req, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create payload: %v", err)
	}

	// Verify
	verifyResp, err := evmFacilitator.Verify(ctx, payload, req)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !verifyResp.IsValid {
		t.Error("Expected valid verification")
	}

	if verifyResp.Payer != clientSigner.Address() {
		t.Errorf("Expected payer %s, got %s", clientSigner.Address(), verifyResp.Payer)
	}

	// Settle
	settleResp, err := evmFacilitator.Settle(ctx, payload, req)
	if err != nil {
		// Just log error but don't fail, expecting some mock limitations?
		// No, mockFacilitatorEvmSigner.WriteContract works.
		// However, VerifyVerified uses signature verification which might fail if typed data doesn't match?
		// Mock VerifyTypedData returns true for known addresses.
		// HashEIP3009Authorization will create a specific hash.
		// mockClientEvmSigner returns dummy signature.
		// mockFacilitatorEvmSigner VerifyTypedData verifies address is known.
		// It doesn't actually check the signature crypto validity (it's a mock).
		// So it should pass.
		t.Fatalf("Settle failed: %v", err)
	}

	if !settleResp.Success {
		t.Error("Expected success settlement")
	}

	if settleResp.Transaction == "" {
		t.Error("Expected transaction hash")
	}
}
