package client

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"x402-go/mechanisms/evm"
	"x402-go/types"

	"github.com/ethereum/go-ethereum/common"
)

// ExactEvmScheme implements the SchemeNetworkClient interface for EVM exact payments (V2)
type ExactEvmScheme struct {
	signer evm.ClientEvmSigner
}

// NewExactEvmScheme creates a new ExactEvmScheme
func NewExactEvmScheme(signer evm.ClientEvmSigner) *ExactEvmScheme {
	return &ExactEvmScheme{
		signer: signer,
	}
}

// Scheme returns the scheme identifier
func (c *ExactEvmScheme) Scheme() string {
	return evm.SchemeExact
}

// CreatePaymentPayload creates a V2 payment payload for the exact scheme
func (c *ExactEvmScheme) CreatePaymentPayload(
	ctx context.Context,
	requirements types.PaymentRequirements,
) (types.PaymentPayload, error) {
	// Validate network
	networkStr := string(requirements.Network)
	if !evm.IsValidNetwork(networkStr) {
		return types.PaymentPayload{}, fmt.Errorf("unsupported network: %s", requirements.Network)
	}

	// Get network configuration
	config, err := evm.GetNetworkConfig(networkStr)
	if err != nil {
		return types.PaymentPayload{}, err
	}

	// Get asset info
	assetInfo, err := evm.GetAssetInfo(networkStr, requirements.Asset)
	if err != nil {
		return types.PaymentPayload{}, err
	}

	// Requirements.Amount is already in the smallest unit
	value, ok := new(big.Int).SetString(requirements.Amount, 10)
	if !ok {
		return types.PaymentPayload{}, fmt.Errorf("invalid amount: %s", requirements.Amount)
	}

	// Create nonce
	nonce, err := evm.CreateNonce()
	if err != nil {
		return types.PaymentPayload{}, err
	}

	// V2 specific: No buffer on validAfter (can use immediately)
	validAfter, validBefore := evm.CreateValidityWindow(time.Hour)

	// Extract extra fields for EIP-3009
	tokenName := assetInfo.Name
	tokenVersion := assetInfo.Version
	if requirements.Extra != nil {
		if name, ok := requirements.Extra["name"].(string); ok {
			tokenName = name
		}
		if ver, ok := requirements.Extra["version"].(string); ok {
			tokenVersion = ver
		}
	}

	// Create authorization
	// Create authorization
	// Determine flow: EIP-3009 (gasless) or ERC-20 (approve + facilitator method)
	// We want to prefer EIP-3009 if supported.

	// Check standard support flag first (static config)
	supportsEIP3009 := assetInfo.SupportsEIP3009

	// If static config says false (or we want to double check), try dynamic check
	if !supportsEIP3009 {
		// Use dynamic check
		// Note: This requires network access. If the signer doesn't support it (e.g. offline keys),
		// this will fail. We should handle that gracefully or assume false.
		// For now, we log/ignore error and assume false if check failed.
		supported, err := evm.VerifyEIP3009Support(ctx, c.signer, config.ChainID, c.signer.Address(), assetInfo.Address)
		if err == nil && supported {
			supportsEIP3009 = true
		}
		// If verification failed (e.g. no RPC), we default to standard ERC-20 flow which works universally
		// (though costs gas for verify).
	}

	if supportsEIP3009 {
		authorization := evm.ExactEIP3009Authorization{
			From:        c.signer.Address(),
			To:          requirements.PayTo,
			Value:       value.String(),
			ValidAfter:  validAfter.String(),
			ValidBefore: validBefore.String(),
			Nonce:       nonce,
		}

		// Sign the authorization
		signature, err := c.signAuthorizationEIP3009(ctx, authorization, config.ChainID, assetInfo.Address, tokenName, tokenVersion)
		if err != nil {
			return types.PaymentPayload{}, fmt.Errorf("failed to sign authorization: %w", err)
		}

		// Create EVM payload
		evmPayload := &evm.ExactEIP3009Payload{
			Signature:     "0x" + hex.EncodeToString(signature),
			Authorization: authorization,
		}

		payloadMap := evmPayload.ToMap()
		payloadMap["type"] = "authorizationEip3009"

		return types.PaymentPayload{
			X402Version: 2,
			Payload:     payloadMap,
		}, nil
	} else {
		// ERC-20 Authorization (Approvals + Facilitator)

		// 1. Check Allowance
		allowanceRes, err := c.signer.ReadContract(
			ctx,
			assetInfo.Address,
			evm.ERC20ABI,
			"allowance",
			common.HexToAddress(c.signer.Address()),
			common.HexToAddress(evm.FacilitatorContractAddress),
		)
		if err != nil {
			return types.PaymentPayload{}, fmt.Errorf("failed to check allowance: %w", err)
		}

		allowance, ok := allowanceRes.(*big.Int)
		if !ok {
			return types.PaymentPayload{}, fmt.Errorf("invalid allowance type returned: %T", allowanceRes)
		}

		// 2. Approve if necessary
		if allowance.Cmp(value) < 0 {
			fmt.Printf("Approving %s for facilitator...\n", value.String())
			txHash, err := c.signer.WriteContract(
				ctx,
				assetInfo.Address,
				evm.ERC20ABI,
				"approve",
				common.HexToAddress(evm.FacilitatorContractAddress),
				value,
			)
			if err != nil {
				return types.PaymentPayload{}, fmt.Errorf("failed to send approve transaction: %w", err)
			}

			// Wait for confirmation
			receipt, err := c.signer.WaitForTransactionReceipt(ctx, txHash)
			if err != nil {
				return types.PaymentPayload{}, fmt.Errorf("failed to wait for approve receipt: %w", err)
			}
			if receipt.Status == 0 {
				return types.PaymentPayload{}, fmt.Errorf("approve transaction failed")
			}
			fmt.Println("Approve transaction confirmed.")
		}

		authorization := evm.ExactERC20Authorization{
			Token:       assetInfo.Address,
			From:        c.signer.Address(),
			To:          requirements.PayTo,
			Value:       value.String(),
			ValidAfter:  validAfter.String(),
			ValidBefore: validBefore.String(),
			Nonce:       nonce,
			NeedApprove: true, // Signal that approval corresponds to this payment
		}

		// Sign the authorization
		// Note: The reference implementation uses "Facilitator" domain name and version "1"
		// which are hardcoded in signAuthorizationERC20
		signature, err := c.signAuthorizationERC20(ctx, authorization, config.ChainID, evm.FacilitatorContractAddress)
		if err != nil {
			return types.PaymentPayload{}, fmt.Errorf("failed to sign authorization: %w", err)
		}

		// Create EVM payload
		evmPayload := &evm.ExactERC20Payload{
			Signature:     "0x" + hex.EncodeToString(signature),
			Authorization: authorization,
		}

		payloadMap := evmPayload.ToMap()
		payloadMap["type"] = "authorization"

		return types.PaymentPayload{
			X402Version: 2,
			Payload:     payloadMap,
		}, nil
	}
}

// signAuthorizationEIP3009 signs the EIP-3009 authorization using EIP-712
func (c *ExactEvmScheme) signAuthorizationEIP3009(
	ctx context.Context,
	authorization evm.ExactEIP3009Authorization,
	chainID *big.Int,
	verifyingContract string,
	tokenName string,
	tokenVersion string,
) ([]byte, error) {
	// Create EIP-712 domain
	domain := evm.TypedDataDomain{
		Name:              tokenName,
		Version:           tokenVersion,
		ChainID:           chainID,
		VerifyingContract: verifyingContract,
	}

	// Define EIP-712 types
	types := map[string][]evm.TypedDataField{
		"EIP712Domain": {
			{Name: "name", Type: "string"},
			{Name: "version", Type: "string"},
			{Name: "chainId", Type: "uint256"},
			{Name: "verifyingContract", Type: "address"},
		},
		"TransferWithAuthorization": {
			{Name: "from", Type: "address"},
			{Name: "to", Type: "address"},
			{Name: "value", Type: "uint256"},
			{Name: "validAfter", Type: "uint256"},
			{Name: "validBefore", Type: "uint256"},
			{Name: "nonce", Type: "bytes32"},
		},
	}

	// Parse values for message
	value, _ := new(big.Int).SetString(authorization.Value, 10)
	validAfter, _ := new(big.Int).SetString(authorization.ValidAfter, 10)
	validBefore, _ := new(big.Int).SetString(authorization.ValidBefore, 10)
	nonceBytes, _ := evm.HexToBytes(authorization.Nonce)

	// Create message
	message := map[string]interface{}{
		"from":        authorization.From,
		"to":          authorization.To,
		"value":       value,
		"validAfter":  validAfter,
		"validBefore": validBefore,
		"nonce":       nonceBytes,
	}

	// Sign the typed data
	return c.signer.SignTypedData(ctx, domain, types, "TransferWithAuthorization", message)
}

// signAuthorizationERC20 signs the ERC-20 authorization using EIP-712
func (c *ExactEvmScheme) signAuthorizationERC20(
	ctx context.Context,
	authorization evm.ExactERC20Authorization,
	chainID *big.Int,
	verifyingContract string,
) ([]byte, error) {
	// Create EIP-712 domain
	// Note: The reference implementation hardcodes name "Facilitator" and version "1" for the domain
	domain := evm.TypedDataDomain{
		Name:              "Facilitator",
		Version:           "1",
		ChainID:           chainID,
		VerifyingContract: verifyingContract,
	}

	// Define EIP-712 types
	types := map[string][]evm.TypedDataField{
		"EIP712Domain": {
			{Name: "name", Type: "string"},
			{Name: "version", Type: "string"},
			{Name: "chainId", Type: "uint256"},
			{Name: "verifyingContract", Type: "address"},
		},
		"tokenTransferWithAuthorization": {
			{Name: "token", Type: "address"},
			{Name: "from", Type: "address"},
			{Name: "to", Type: "address"},
			{Name: "value", Type: "uint256"},
			{Name: "validAfter", Type: "uint256"},
			{Name: "validBefore", Type: "uint256"},
			{Name: "nonce", Type: "bytes32"},
			{Name: "needApprove", Type: "bool"},
		},
	}

	// Parse values for message
	value, _ := new(big.Int).SetString(authorization.Value, 10)
	validAfter, _ := new(big.Int).SetString(authorization.ValidAfter, 10)
	validBefore, _ := new(big.Int).SetString(authorization.ValidBefore, 10)
	nonceBytes, _ := evm.HexToBytes(authorization.Nonce)

	// Create message
	message := map[string]interface{}{
		"token":       authorization.Token,
		"from":        authorization.From,
		"to":          authorization.To,
		"value":       value,
		"validAfter":  validAfter,
		"validBefore": validBefore,
		"nonce":       nonceBytes,
		"needApprove": authorization.NeedApprove,
	}

	// Sign the typed data
	return c.signer.SignTypedData(ctx, domain, types, "tokenTransferWithAuthorization", message)
}
