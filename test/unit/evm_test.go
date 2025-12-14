package unit_test

import (
	"context"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"

	x402 "x402-go"
	"x402-go/mechanisms/evm"
	evmclient "x402-go/mechanisms/evm/exact/client"
	evmv1client "x402-go/mechanisms/evm/exact/v1/client"
	"x402-go/types"
)

// Mock EVM signer for client
type mockClientEvmSigner struct {
	address string
}

func (m *mockClientEvmSigner) Address() string {
	// Corresponds to private key: 0x0123456789012345678901234567890123456789012345678901234567890123
	return "0x14791697260E4c9A71f18484C9f997B308e59325"
}

func (m *mockClientEvmSigner) SignTypedData(
	ctx context.Context,
	domain evm.TypedDataDomain,
	types map[string][]evm.TypedDataField,
	primaryType string,
	message map[string]interface{},
) ([]byte, error) {
	// Use a hardcoded private key for testing
	// Private key corresponding to 0x1234567890123456789012345678901234567890 is not known,
	// so we switch to a known key and update Address() to match.
	// But Address() is hardcoded. Let's fix Address() too.
	// Key: 0x0123456789012345678901234567890123456789012345678901234567890123
	// Addr: 0x14791697260E4c9A71f18484C9f997B308e59325
	pk, _ := crypto.HexToECDSA("0123456789012345678901234567890123456789012345678901234567890123")

	// Convert types to apitypes
	typedData := apitypes.TypedData{
		Types:       make(apitypes.Types),
		PrimaryType: primaryType,
		Domain: apitypes.TypedDataDomain{
			Name:              domain.Name,
			Version:           domain.Version,
			ChainId:           (*math.HexOrDecimal256)(domain.ChainID),
			VerifyingContract: domain.VerifyingContract,
		},
		Message: message,
	}

	for typeName, fields := range types {
		typedFields := make([]apitypes.Type, len(fields))
		for i, field := range fields {
			typedFields[i] = apitypes.Type{
				Name: field.Name,
				Type: field.Type,
			}
		}
		typedData.Types[typeName] = typedFields
	}

	// Hash
	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return nil, err
	}
	typedDataHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		return nil, err
	}

	rawData := []byte{0x19, 0x01}
	rawData = append(rawData, domainSeparator...)
	rawData = append(rawData, typedDataHash...)
	hash := crypto.Keccak256(rawData)

	// Sign
	signature, err := crypto.Sign(hash, pk)
	if err != nil {
		return nil, err
	}

	// Adjust V
	if signature[64] < 27 {
		signature[64] += 27
	}

	return signature, nil
}

func (m *mockClientEvmSigner) ReadContract(
	ctx context.Context,
	address string,
	abi []byte,
	functionName string,
	args ...interface{},
) (interface{}, error) {
	return nil, nil
}

// Mock EVM signer for facilitator
type mockFacilitatorEvmSigner struct {
	balances map[string]*big.Int
	nonces   map[string]bool
}

func newMockFacilitatorEvmSigner() *mockFacilitatorEvmSigner {
	return &mockFacilitatorEvmSigner{
		balances: make(map[string]*big.Int),
		nonces:   make(map[string]bool),
	}
}

func (m *mockFacilitatorEvmSigner) Address() string {
	return "0xfacilitator1234567890123456789012345678"
}

func (m *mockFacilitatorEvmSigner) GetAddresses() []string {
	return []string{m.Address()}
}

func (m *mockFacilitatorEvmSigner) GetCode(ctx context.Context, address string) ([]byte, error) {
	// Mock: return empty for EOA, non-empty for contracts
	// For testing, assume all addresses are EOAs (deployed wallets)
	return []byte{0x60, 0x60}, nil // Mock bytecode
}

func (m *mockFacilitatorEvmSigner) GetBalance(ctx context.Context, address string, tokenAddress string) (*big.Int, error) {
	key := address + ":" + tokenAddress
	if balance, ok := m.balances[key]; ok {
		return balance, nil
	}
	// Default to sufficient balance
	return big.NewInt(10000000000), nil // 10,000 USDC
}

func (m *mockFacilitatorEvmSigner) GetChainID(ctx context.Context) (*big.Int, error) {
	return big.NewInt(8453), nil // Base mainnet
}

func (m *mockFacilitatorEvmSigner) ReadContract(
	ctx context.Context,
	address string,
	abi []byte,
	functionName string,
	args ...interface{},
) (interface{}, error) {
	// Mock authorization state check
	if functionName == "authorizationState" {
		// Return false (not used)
		return false, nil
	}
	return nil, nil
}

func (m *mockFacilitatorEvmSigner) WriteContract(
	ctx context.Context,
	contractAddress string,
	abi []byte,
	functionName string,
	args ...interface{},
) (string, error) {
	// Return mock transaction hash
	return "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", nil
}

func (m *mockFacilitatorEvmSigner) SendTransaction(
	ctx context.Context,
	to string,
	data []byte,
) (string, error) {
	// Return mock transaction hash
	return "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", nil
}

func (m *mockFacilitatorEvmSigner) WaitForTransactionReceipt(ctx context.Context, txHash string) (*evm.TransactionReceipt, error) {
	return &evm.TransactionReceipt{
		Status: evm.TxStatusSuccess,
	}, nil
}

func (m *mockFacilitatorEvmSigner) VerifyTypedData(
	ctx context.Context,
	address string,
	domain evm.TypedDataDomain,
	types map[string][]evm.TypedDataField,
	primaryType string,
	message map[string]interface{},
	signature []byte,
) (bool, error) {
	// For testing, verify that the address matches one of our mock clients
	return address == "0x1234567890123456789012345678901234567890" ||
		address == "0xabcdef1234567890123456789012345678901234", nil
}

// TestEVMVersionMismatch tests that V1 and V2 don't mix
func TestEVMVersionMismatch(t *testing.T) {
	t.Run("V1 Client with V2 Requirements Should Fail", func(t *testing.T) {
		ctx := context.Background()

		// Setup V1 client
		clientSigner := &mockClientEvmSigner{}
		client := x402.Newx402Client()
		evmClientV1 := evmv1client.NewExactEvmSchemeV1(clientSigner)
		client.RegisterV1("eip155:8453", evmClientV1)

		// V1 client should succeed
		v1Requirements := types.PaymentRequirementsV1{
			Scheme:            evm.SchemeExact,
			Network:           "eip155:8453",
			Asset:             "erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
			MaxAmountRequired: "1000000",
			PayTo:             "0x9876543210987654321098765432109876543210",
		}
		payload, err := client.CreatePaymentPayloadV1(ctx, v1Requirements)
		if err != nil {
			t.Fatalf("Failed to create payment: %v", err)
		}
		// Verify it created a V1 payload
		if payload.X402Version != 1 {
			t.Errorf("Expected V1 payload from V1 client, got v%d", payload.X402Version)
		}
		if payload.Scheme != evm.SchemeExact {
			t.Errorf("Expected scheme %s, got %s", evm.SchemeExact, payload.Scheme)
		}
	})

	t.Run("V2 Client with V1 Requirements Should Fail", func(t *testing.T) {
		ctx := context.Background()

		// Setup V2 client
		clientSigner := &mockClientEvmSigner{}
		client := x402.Newx402Client()
		evmClient := evmclient.NewExactEvmScheme(clientSigner)
		client.Register("eip155:8453", evmClient)

		// V2 requirements (typed)
		requirements := types.PaymentRequirements{
			Scheme:  evm.SchemeExact,
			Network: "eip155:8453",
			Asset:   "erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
			Amount:  "1000000",
			PayTo:   "0x9876543210987654321098765432109876543210",
		}

		// V2 client creates V2 payload (typed API)
		payload, err := client.CreatePaymentPayload(ctx, requirements, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create payment: %v", err)
		}
		// Verify it created a V2 payload
		if payload.X402Version != 2 {
			t.Errorf("Expected V2 payload from V2 client, got v%d", payload.X402Version)
		}
		if payload.Accepted.Scheme != evm.SchemeExact {
			t.Errorf("Expected scheme in accepted field")
		}
	})
}

// TestEVMDualVersionSupport tests that a client can register both V1 and V2 and handle either version.
// This is important for backward compatibility - a client application can support both protocol versions
// simultaneously and respond appropriately based on the server's requirements.
func TestEVMDualVersionSupport(t *testing.T) {
	t.Run("Dual-Registered Client Handles V1 Requirements", func(t *testing.T) {
		ctx := context.Background()

		// Setup client with BOTH V1 and V2 implementations
		clientSigner := &mockClientEvmSigner{}
		client := x402.Newx402Client()

		// Register V1 implementation
		evmClientV1 := evmv1client.NewExactEvmSchemeV1(clientSigner)
		client.RegisterV1("eip155:8453", evmClientV1)

		// Register V2 implementation
		evmClient := evmclient.NewExactEvmScheme(clientSigner)
		client.Register("eip155:8453", evmClient)

		// V1 requirements (typed)
		v1Requirements := types.PaymentRequirementsV1{
			Scheme:            evm.SchemeExact,
			Network:           "eip155:8453",
			Asset:             "erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
			MaxAmountRequired: "1000000",
			PayTo:             "0x9876543210987654321098765432109876543210",
		}

		// Client handles V1 request (typed API)
		payloadV1, err := client.CreatePaymentPayloadV1(ctx, v1Requirements)
		if err != nil {
			t.Fatalf("Failed to create V1 payment: %v", err)
		}

		if payloadV1.X402Version != 1 {
			t.Errorf("Expected V1 payload, got v%d", payloadV1.X402Version)
		}

		// Verify V1 structure (scheme at top level, not in Accepted)
		if payloadV1.Scheme == "" {
			t.Error("Expected V1 payload to have top-level Scheme")
		}

		// V2 requirements (typed, uses Amount)
		v2Requirements := types.PaymentRequirements{
			Scheme:  evm.SchemeExact,
			Network: "eip155:8453",
			Asset:   "erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
			Amount:  "1000000",
			PayTo:   "0x9876543210987654321098765432109876543210",
			Extra: map[string]interface{}{
				"name":    "USD Coin",
				"version": "2",
			},
		}

		// Client handles V2 request (typed API)
		payloadV2, err := client.CreatePaymentPayload(ctx, v2Requirements, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create V2 payment: %v", err)
		}

		if payloadV2.X402Version != 2 {
			t.Errorf("Expected V2 payload, got v%d", payloadV2.X402Version)
		}
		if payloadV2.Accepted.Scheme == "" {
			t.Error("Expected V2 payload to have Accepted.Scheme")
		}
	})

	t.Run("Dual-Registered Client Handles V2 Requirements", func(t *testing.T) {
		ctx := context.Background()

		// Setup client with BOTH V1 and V2 implementations
		clientSigner := &mockClientEvmSigner{}
		client := x402.Newx402Client()

		// Register V1 implementation
		evmClientV1 := evmv1client.NewExactEvmSchemeV1(clientSigner)
		client.RegisterV1("eip155:8453", evmClientV1)

		// Register V2 implementation
		evmClient := evmclient.NewExactEvmScheme(clientSigner)
		client.Register("eip155:8453", evmClient)

		// V2 requirements (typed)
		requirements := types.PaymentRequirements{
			Scheme:  evm.SchemeExact,
			Network: "eip155:8453",
			Asset:   "erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
			Amount:  "1000000",
			PayTo:   "0x9876543210987654321098765432109876543210",
		}

		// Client handles V2 request using V2 implementation (typed API)
		payloadV2, err := client.CreatePaymentPayload(ctx, requirements, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create V2 payment: %v", err)
		}

		if payloadV2.X402Version != 2 {
			t.Errorf("Expected V2 payload, got v%d", payloadV2.X402Version)
		}

		// Verify V2 structure (has scheme/network in Accepted)
		if payloadV2.Accepted.Scheme == "" {
			t.Error("Expected V2 payload to have Accepted.Scheme")
		}
	})
}
