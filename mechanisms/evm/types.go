package evm

import (
	"context"
	"math/big"
)

// ExactEIP3009Authorization represents the EIP-3009 TransferWithAuthorization data
type ExactEIP3009Authorization struct {
	From        string `json:"from"`        // Ethereum address (hex)
	To          string `json:"to"`          // Ethereum address (hex)
	Value       string `json:"value"`       // Amount in wei as string
	ValidAfter  string `json:"validAfter"`  // Unix timestamp as string
	ValidBefore string `json:"validBefore"` // Unix timestamp as string
	Nonce       string `json:"nonce"`       // 32-byte nonce as hex string
}

// ExactEIP3009Payload represents the exact payment payload for EVM networks
type ExactEIP3009Payload struct {
	Signature     string                    `json:"signature,omitempty"`
	Authorization ExactEIP3009Authorization `json:"authorization"`
}

// ExactEvmPayloadV1 is an alias for ExactEIP3009Payload (v1 compatibility)
type ExactEvmPayloadV1 = ExactEIP3009Payload

// ExactEvmPayloadV2 is an alias for ExactEIP3009Payload (v2 compatibility)
type ExactEvmPayloadV2 = ExactEIP3009Payload

// ExactERC20Authorization represents the ERC20 TransferWithAuthorization data
type ExactERC20Authorization struct {
	Token       string `json:"token"`       // Token address (hex)
	From        string `json:"from"`        // Ethereum address (hex)
	To          string `json:"to"`          // Ethereum address (hex)
	Value       string `json:"value"`       // Amount in wei as string
	ValidAfter  string `json:"validAfter"`  // Unix timestamp as string
	ValidBefore string `json:"validBefore"` // Unix timestamp as string
	Nonce       string `json:"nonce"`       // 32-byte nonce as hex string
	NeedApprove bool   `json:"needApprove"` // Whether to approve the token transfer
}

// ExactERC20Payload represents the exact payment payload for ERC20 authorization
type ExactERC20Payload struct {
	Signature     string                  `json:"signature,omitempty"`
	Authorization ExactERC20Authorization `json:"authorization"`
}

// ToMap converts an ExactERC20Payload to a map for JSON marshaling
func (p *ExactERC20Payload) ToMap() map[string]interface{} {
	result := map[string]interface{}{
		"authorization": map[string]interface{}{
			"token":       p.Authorization.Token,
			"from":        p.Authorization.From,
			"to":          p.Authorization.To,
			"value":       p.Authorization.Value,
			"validAfter":  p.Authorization.ValidAfter,
			"validBefore": p.Authorization.ValidBefore,
			"nonce":       p.Authorization.Nonce,
			"needApprove": p.Authorization.NeedApprove,
		},
	}
	if p.Signature != "" {
		result["signature"] = p.Signature
	}
	return result
}

// ContractReader defines the interface for reading from a smart contract
type ContractReader interface {
	ReadContract(ctx context.Context, address string, abi []byte, functionName string, args ...interface{}) (interface{}, error)
}

// ClientEvmSigner defines the interface for client-side EVM signing operations
type ClientEvmSigner interface {
	// Address returns the signer's Ethereum address
	Address() string

	// SignTypedData signs EIP-712 typed data
	SignTypedData(ctx context.Context, domain TypedDataDomain, types map[string][]TypedDataField, primaryType string, message map[string]interface{}) ([]byte, error)

	// ReadContract reads data from a smart contract
	// Required for dynamic feature detection (e.g. EIP-3009 support)
	// Implementations without network access should return an error
	ReadContract(ctx context.Context, address string, abi []byte, functionName string, args ...interface{}) (interface{}, error)

	// WriteContract executes a smart contract transaction
	// Required for on-chain operations like ERC-20 approvals
	WriteContract(ctx context.Context, address string, abi []byte, functionName string, args ...interface{}) (string, error)

	// WaitForTransactionReceipt waits for a transaction to be mined
	WaitForTransactionReceipt(ctx context.Context, txHash string) (*TransactionReceipt, error)
}

// FacilitatorEvmSigner defines the interface for facilitator EVM operations
// Supports multiple addresses for load balancing, key rotation, and high availability
type FacilitatorEvmSigner interface {
	// GetAddresses returns all addresses this facilitator can use for signing
	// Enables dynamic address selection for load balancing and key rotation
	GetAddresses() []string

	// ReadContract reads data from a smart contract
	ReadContract(ctx context.Context, address string, abi []byte, functionName string, args ...interface{}) (interface{}, error)

	// VerifyTypedData verifies an EIP-712 signature
	VerifyTypedData(ctx context.Context, address string, domain TypedDataDomain, types map[string][]TypedDataField, primaryType string, message map[string]interface{}, signature []byte) (bool, error)

	// WriteContract executes a smart contract transaction
	WriteContract(ctx context.Context, address string, abi []byte, functionName string, args ...interface{}) (string, error)

	// SendTransaction sends a raw transaction with arbitrary calldata
	// Used for smart wallet deployment where calldata is pre-encoded
	SendTransaction(ctx context.Context, to string, data []byte) (string, error)

	// WaitForTransactionReceipt waits for a transaction to be mined
	WaitForTransactionReceipt(ctx context.Context, txHash string) (*TransactionReceipt, error)

	// GetBalance gets the balance of an address for a specific token
	GetBalance(ctx context.Context, address string, tokenAddress string) (*big.Int, error)

	// GetChainID returns the chain ID of the connected network
	GetChainID(ctx context.Context) (*big.Int, error)

	// GetCode returns the bytecode at the given address
	// Returns empty slice if address is an EOA or doesn't exist
	GetCode(ctx context.Context, address string) ([]byte, error)
}

// TypedDataDomain represents the EIP-712 domain separator
type TypedDataDomain struct {
	Name              string   `json:"name"`
	Version           string   `json:"version"`
	ChainID           *big.Int `json:"chainId"`
	VerifyingContract string   `json:"verifyingContract"`
}

// TypedDataField represents a field in EIP-712 typed data
type TypedDataField struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// TransactionReceipt represents the receipt of a mined transaction
type TransactionReceipt struct {
	Status      uint64 `json:"status"`
	BlockNumber uint64 `json:"blockNumber"`
	TxHash      string `json:"transactionHash"`
}

// AssetInfo contains information about an ERC20 token
type AssetInfo struct {
	Address         string
	Name            string
	Version         string
	Decimals        int
	SupportsEIP3009 bool
}

// NetworkConfig contains network-specific configuration
type NetworkConfig struct {
	ChainID         *big.Int
	DefaultAsset    AssetInfo
	SupportedAssets map[string]AssetInfo // symbol -> AssetInfo
}

// PayloadToMap converts an ExactEIP3009Payload to a map for JSON marshaling
func (p *ExactEIP3009Payload) ToMap() map[string]interface{} {
	result := map[string]interface{}{
		"authorization": map[string]interface{}{
			"from":        p.Authorization.From,
			"to":          p.Authorization.To,
			"value":       p.Authorization.Value,
			"validAfter":  p.Authorization.ValidAfter,
			"validBefore": p.Authorization.ValidBefore,
			"nonce":       p.Authorization.Nonce,
		},
	}
	if p.Signature != "" {
		result["signature"] = p.Signature
	}
	return result
}

// PayloadFromMap creates an ExactEIP3009Payload from a map
func PayloadFromMap(data map[string]interface{}) (*ExactEIP3009Payload, error) {
	payload := &ExactEIP3009Payload{}

	if sig, ok := data["signature"].(string); ok {
		payload.Signature = sig
	}

	if auth, ok := data["authorization"].(map[string]interface{}); ok {
		if from, ok := auth["from"].(string); ok {
			payload.Authorization.From = from
		}
		if to, ok := auth["to"].(string); ok {
			payload.Authorization.To = to
		}
		if value, ok := auth["value"].(string); ok {
			payload.Authorization.Value = value
		}
		if validAfter, ok := auth["validAfter"].(string); ok {
			payload.Authorization.ValidAfter = validAfter
		}
		if validBefore, ok := auth["validBefore"].(string); ok {
			payload.Authorization.ValidBefore = validBefore
		}
		if nonce, ok := auth["nonce"].(string); ok {
			payload.Authorization.Nonce = nonce
		}
	}

	return payload, nil
}

// PayloadFromMap creates an ExactEIP3009Payload or ExactERC20Payload from a map.
// Note: Since both payloads share the same underlying struct for Authorization (mostly),
// and ExactEIP3009Payload is the legacy/standard return type, we currently map everything
// to that structure where possible or handle the extension fields.
//
// Ideally, this should return a wrapper or interface, but for now we will assume the caller
// knows what to expect or checks the fields.
// However, to support the new ExactERC20Payload, we might need a more flexible return type or
// just reuse the existing one if it fits.
//
// Actually, looking at types.go, ExactEIP3009Authorization is missing 'Token' and 'NeedApprove'.
// We need to update ExactEIP3009Payload or use a Union type.
// Given strict typing, we might need a separate parser or expand ExactEIP3009Authorization?
// Expanding ExactEIP3009Authorization involves changing the spec.
//
// Instead, let's allow returning a pointer to ExactEIP3009Payload OR ExactERC20Payload.
// But Go doesn't support sum types easily.
//
// Let's modify PayloadFromMap to return interface{} or check input.
// Alternatively, since ExactEvmScheme uses this, and it needs to handle both...
//
// Let's UPDATE ExactEIP3009Authorization to include optional Token and NeedApprove?
// No, that mixes EIP-3009 and ERC-20 auth.
//
// Let's add a specialized function PayloadERC20FromMap.
func PayloadERC20FromMap(data map[string]interface{}) (*ExactERC20Payload, error) {
	payload := &ExactERC20Payload{}

	if sig, ok := data["signature"].(string); ok {
		payload.Signature = sig
	}

	if auth, ok := data["authorization"].(map[string]interface{}); ok {
		if token, ok := auth["token"].(string); ok {
			payload.Authorization.Token = token
		}
		if from, ok := auth["from"].(string); ok {
			payload.Authorization.From = from
		}
		if to, ok := auth["to"].(string); ok {
			payload.Authorization.To = to
		}
		if value, ok := auth["value"].(string); ok {
			payload.Authorization.Value = value
		}
		if validAfter, ok := auth["validAfter"].(string); ok {
			payload.Authorization.ValidAfter = validAfter
		}
		if validBefore, ok := auth["validBefore"].(string); ok {
			payload.Authorization.ValidBefore = validBefore
		}
		if nonce, ok := auth["nonce"].(string); ok {
			payload.Authorization.Nonce = nonce
		}
		if needApprove, ok := auth["needApprove"].(bool); ok {
			payload.Authorization.NeedApprove = needApprove
		}
	}

	return payload, nil
}

// IsValidNetwork checks if the network is supported for EVM
func IsValidNetwork(network string) bool {
	switch network {
	case "eip155:1", "eip155:8453", "eip155:84532", "base", "base-sepolia", "base-mainnet":
		return true
	default:
		return false
	}
}

// ERC6492SignatureData represents the parsed components of an ERC-6492 signature
// ERC-6492 allows signatures from undeployed smart contract accounts by wrapping
// the signature with deployment information (factory address and calldata)
type ERC6492SignatureData struct {
	Factory         [20]byte // CREATE2 factory address (zero address if not ERC-6492)
	FactoryCalldata []byte   // Calldata to deploy the wallet (empty if not ERC-6492)
	InnerSignature  []byte   // The actual signature (EIP-1271 or EOA)
}
