package evm

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// GetEvmChainId returns the chain ID for a given network
func GetEvmChainId(network string) (*big.Int, error) {
	networkStr := network

	// Normalize network name
	switch networkStr {
	case "base", "base-mainnet":
		networkStr = "eip155:8453"
	case "base-sepolia":
		networkStr = "eip155:84532"
	}

	if config, ok := NetworkConfigs[networkStr]; ok {
		return config.ChainID, nil
	}

	// Try to parse from CAIP-2 format (eip155:chainId)
	if strings.HasPrefix(networkStr, "eip155:") {
		chainIdStr := strings.TrimPrefix(networkStr, "eip155:")
		chainId, ok := new(big.Int).SetString(chainIdStr, 10)
		if ok {
			return chainId, nil
		}
	}

	return nil, fmt.Errorf("unsupported network: %s", network)
}

// CreateNonce generates a random 32-byte nonce
func CreateNonce() (string, error) {
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	if err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	return "0x" + hex.EncodeToString(nonce), nil
}

// NormalizeAddress ensures an Ethereum address is in the correct format
func NormalizeAddress(address string) string {
	// Remove 0x prefix if present
	addr := strings.TrimPrefix(strings.ToLower(address), "0x")

	// Add 0x prefix back
	return "0x" + addr
}

// IsValidAddress checks if a string is a valid Ethereum address
func IsValidAddress(address string) bool {
	// Remove 0x prefix if present
	addr := strings.TrimPrefix(address, "0x")

	// Check length (40 hex characters)
	if len(addr) != 40 {
		return false
	}

	// Check if all characters are valid hex
	_, err := hex.DecodeString(addr)
	return err == nil
}

// ParseAmount converts a decimal string amount to wei based on token decimals
func ParseAmount(amount string, decimals int) (*big.Int, error) {
	// Parse the decimal amount
	parts := strings.Split(amount, ".")
	if len(parts) > 2 {
		return nil, fmt.Errorf("invalid amount format: %s", amount)
	}

	// Parse integer part
	intPart, ok := new(big.Int).SetString(parts[0], 10)
	if !ok {
		return nil, fmt.Errorf("invalid integer part: %s", parts[0])
	}

	// Handle decimal part
	decPart := new(big.Int)
	if len(parts) == 2 && parts[1] != "" {
		// Pad or truncate decimal part to match token decimals
		decStr := parts[1]
		if len(decStr) > decimals {
			decStr = decStr[:decimals]
		} else {
			decStr += strings.Repeat("0", decimals-len(decStr))
		}

		decPart, ok = new(big.Int).SetString(decStr, 10)
		if !ok {
			return nil, fmt.Errorf("invalid decimal part: %s", parts[1])
		}
	}

	// Calculate total in smallest unit
	multiplier := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil)
	result := new(big.Int).Mul(intPart, multiplier)
	result.Add(result, decPart)

	return result, nil
}

// FormatAmount converts an amount in wei to a decimal string
func FormatAmount(amount *big.Int, decimals int) string {
	if amount == nil {
		return "0"
	}

	divisor := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil)
	quotient, remainder := new(big.Int).DivMod(amount, divisor, new(big.Int))

	// Format the decimal part with leading zeros
	decStr := remainder.String()
	if len(decStr) < decimals {
		decStr = strings.Repeat("0", decimals-len(decStr)) + decStr
	}

	// Remove trailing zeros
	decStr = strings.TrimRight(decStr, "0")

	if decStr == "" {
		return quotient.String()
	}

	return quotient.String() + "." + decStr
}

// GetNetworkConfig returns the configuration for a network
func GetNetworkConfig(network string) (*NetworkConfig, error) {
	networkStr := network

	// Normalize network name
	switch networkStr {
	case "base", "base-mainnet":
		networkStr = "eip155:8453"
	case "base-sepolia":
		networkStr = "eip155:84532"
	}

	if config, ok := NetworkConfigs[networkStr]; ok {
		return &config, nil
	}

	return nil, fmt.Errorf("unsupported network: %s", network)
}

// GetAssetInfo returns information about an asset on a network
func GetAssetInfo(network string, assetSymbolOrAddress string) (*AssetInfo, error) {
	config, err := GetNetworkConfig(network)
	if err != nil {
		return nil, err
	}

	// Check if it's an address
	if IsValidAddress(assetSymbolOrAddress) {
		// For now, assume it's USDC if the address matches
		normalizedAddr := NormalizeAddress(assetSymbolOrAddress)
		if normalizedAddr == NormalizeAddress(config.DefaultAsset.Address) {
			return &config.DefaultAsset, nil
		}
		// Could extend this to support more tokens
		return &AssetInfo{
			Address:  normalizedAddr,
			Name:     "Unknown Token",
			Version:  "1",
			Decimals: 18, // Default to 18 decimals for unknown tokens
		}, nil
	}

	// Look up by symbol
	if asset, ok := config.SupportedAssets[strings.ToUpper(assetSymbolOrAddress)]; ok {
		return &asset, nil
	}

	// Default to the network's default asset
	return &config.DefaultAsset, nil
}

// CreateValidityWindow creates valid after/before timestamps
func CreateValidityWindow(duration time.Duration) (validAfter, validBefore *big.Int) {
	now := time.Now().Unix()
	// Add 30 second buffer to account for clock skew and block time
	validAfter = big.NewInt(now - 30)
	validBefore = big.NewInt(now + int64(duration.Seconds()))
	return validAfter, validBefore
}

// HexToBytes converts a hex string to bytes
func HexToBytes(hexStr string) ([]byte, error) {
	// Remove 0x prefix if present
	cleaned := strings.TrimPrefix(hexStr, "0x")
	return hex.DecodeString(cleaned)
}

// VerifyEIP3009Support checks if a token contract supports EIP-3009 transferWithAuthorization.
// It simulates a call with a random valid-looking signature.
// If the call reverts with "invalid signature" (or similar), it means the function exists.
// If it reverts because function selector not found (fallback), it means not supported.
// EIP3009SupportCache caches the support status (supported, unsupported) for tokens on chains
// Key format: "chainID:tokenAddress"
var EIP3009SupportCache sync.Map

// VerifyEIP3009Support checks if a token contract supports EIP-3009 transferWithAuthorization.
// It simulates a call with a random valid-looking signature.
// If the call reverts with "invalid signature" (or similar), it means the function exists.
// If it reverts because function selector not found (fallback), it means not supported.
func VerifyEIP3009Support(ctx context.Context, reader ContractReader, chainID *big.Int, fromAddress string, tokenAddress string) (bool, error) {
	// Check cache first
	cacheKey := fmt.Sprintf("%s:%s", chainID.String(), strings.ToLower(tokenAddress))
	if val, ok := EIP3009SupportCache.Load(cacheKey); ok {
		return val.(bool), nil
	}

	// EIP-3009 transferWithAuthorization selector: e3ee160e
	// transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)
	// We use the VRS version as it's the standard for EOAs.

	// Construct a dummy call
	from := common.HexToAddress(fromAddress)
	to := common.HexToAddress(fromAddress) // Self for safety
	value := big.NewInt(0)
	validAfter := big.NewInt(0)
	validBefore := big.NewInt(0)
	var nonce [32]byte

	// Dummy signature parts
	var v uint8 = 27
	var r [32]byte
	var s [32]byte

	// Create minimal ABI for just this function
	minimalABI := []byte(`[
		{
			"inputs": [
				{"name": "from", "type": "address"},
				{"name": "to", "type": "address"},
				{"name": "value", "type": "uint256"},
				{"name": "validAfter", "type": "uint256"},
				{"name": "validBefore", "type": "uint256"},
				{"name": "nonce", "type": "bytes32"},
				{"name": "v", "type": "uint8"},
				{"name": "r", "type": "bytes32"},
				{"name": "s", "type": "bytes32"}
			],
			"name": "transferWithAuthorization",
			"outputs": [],
			"stateMutability": "nonpayable",
			"type": "function"
		}
	]`)

	// Perform read (simulation)
	// We expect this to fail, but HOW it fails tells us if supported.
	_, err := reader.ReadContract(
		ctx,
		tokenAddress,
		minimalABI,
		"transferWithAuthorization",
		from,
		to,
		value,
		validAfter,
		validBefore,
		nonce,
		v,
		r,
		s,
	)

	var supported bool
	if err == nil {
		// Verify surprising success (maybe it accepts anything?)
		supported = true
	} else {
		// Check error message
		errStr := err.Error()

		// If revert contains "signature" or specific EIP-3009 errors, it's supported
		if strings.Contains(strings.ToLower(errStr), "signature") ||
			strings.Contains(strings.ToLower(errStr), "authorization") ||
			strings.Contains(strings.ToLower(errStr), "nonce") {
			supported = true
		} else {
			supported = false
		}
	}

	// Update cache
	EIP3009SupportCache.Store(cacheKey, supported)

	return supported, nil
}
