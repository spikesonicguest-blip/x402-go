package evm

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"

	x402evm "x402-go/mechanisms/evm"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/ethclient"
)

// ClientSigner implements x402evm.ClientEvmSigner using an ECDSA private key.
// This provides client-side EIP-712 signing for creating payment payloads.
type ClientSigner struct {
	privateKey *ecdsa.PrivateKey
	address    common.Address
	ethClient  *ethclient.Client
}

// NewClientSignerFromPrivateKey creates a client signer from a hex-encoded private key.
//
// Args:
//
//	privateKeyHex: Hex-encoded private key (with or without "0x" prefix)
//
// Returns:
//
//	ClientEvmSigner implementation ready for use with evm.NewExactEvmClient()
//	Error if private key is invalid
//
// Example:
//
//	signer, err := evm.NewClientSignerFromPrivateKey("0x1234...")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	client := x402.Newx402Client().
//	    Register("eip155:*", evm.NewExactEvmClient(signer))
func NewClientSignerFromPrivateKey(privateKeyHex string) (x402evm.ClientEvmSigner, error) {
	// Strip 0x prefix if present
	privateKeyHex = strings.TrimPrefix(privateKeyHex, "0x")

	// Parse hex string to ECDSA private key
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	// Derive Ethereum address from public key
	address := crypto.PubkeyToAddress(privateKey.PublicKey)

	return &ClientSigner{
		privateKey: privateKey,
		address:    address,
	}, nil
}

// Connect connects the signer to an RPC endpoint
func (s *ClientSigner) Connect(rpcURL string) error {
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return fmt.Errorf("failed to connect to RPC: %w", err)
	}
	s.ethClient = client
	return nil
}

// Address returns the Ethereum address of the signer.
func (s *ClientSigner) Address() string {
	return s.address.Hex()
}

// SignTypedData signs EIP-712 typed data.
//
// Args:
//
//	ctx: Context for cancellation and timeout control
//	domain: EIP-712 domain separator
//	types: Type definitions for the structured data
//	primaryType: The primary type being signed
//	message: The message data to sign
//
// Returns:
//
//	65-byte signature (r, s, v)
//	Error if signing fails
func (s *ClientSigner) SignTypedData(
	ctx context.Context,
	domain x402evm.TypedDataDomain,
	types map[string][]x402evm.TypedDataField,
	primaryType string,
	message map[string]interface{},
) ([]byte, error) {
	// Convert x402 types to go-ethereum apitypes
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

	// Convert field types
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

	// Add EIP712Domain type if not present
	if _, exists := typedData.Types["EIP712Domain"]; !exists {
		typedData.Types["EIP712Domain"] = []apitypes.Type{
			{Name: "name", Type: "string"},
			{Name: "version", Type: "string"},
			{Name: "chainId", Type: "uint256"},
			{Name: "verifyingContract", Type: "address"},
		}
	}

	// Hash the struct data
	dataHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		return nil, fmt.Errorf("failed to hash struct: %w", err)
	}

	// Hash the domain
	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return nil, fmt.Errorf("failed to hash domain: %w", err)
	}

	// Create EIP-712 digest: 0x19 0x01 <domainSeparator> <dataHash>
	rawData := []byte{0x19, 0x01}
	rawData = append(rawData, domainSeparator...)
	rawData = append(rawData, dataHash...)
	digest := crypto.Keccak256(rawData)

	// Sign the digest with ECDSA
	signature, err := crypto.Sign(digest, s.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	// Adjust v value for Ethereum (recovery ID 0/1 → 27/28)
	signature[64] += 27

	return signature, nil
}

// ReadContract reads data from a smart contract
func (s *ClientSigner) ReadContract(
	ctx context.Context,
	contractAddress string,
	abiJSON []byte,
	functionName string,
	args ...interface{},
) (interface{}, error) {
	if s.ethClient == nil {
		return nil, fmt.Errorf("RPC client not configured")
	}

	// Parse ABI
	parsedABI, err := abi.JSON(strings.NewReader(string(abiJSON)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse ABI: %w", err)
	}

	// Pack data
	data, err := parsedABI.Pack(functionName, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to pack data: %w", err)
	}

	// Call contract
	to := common.HexToAddress(contractAddress)
	msg := ethereum.CallMsg{
		To:   &to,
		Data: data,
	}

	resultBytes, err := s.ethClient.CallContract(ctx, msg, nil)
	if err != nil {
		// Detect revert
		return nil, err
	}

	// Unpack result
	// Note: We don't know the return type structure easily here without reflection or more info.
	// However, Unpack usually returns []interface{}.
	// If the method has a single return value, we might want to unwrap it.
	// But Facilitator implementation might expect specific things.

	// Assuming single return or checking how it's used.
	// In the use case for checking support, we actually just care if it reverts or not.
	// But implementing strictly:

	unpacked, err := parsedABI.Unpack(functionName, resultBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack result: %w", err)
	}

	if len(unpacked) == 0 {
		return nil, nil
	}
	if len(unpacked) == 1 {
		return unpacked[0], nil
	}
	return unpacked, nil
}

// WriteContract executes a smart contract transaction
func (s *ClientSigner) WriteContract(
	ctx context.Context,
	contractAddress string,
	abiJSON []byte,
	functionName string,
	args ...interface{},
) (string, error) {
	if s.ethClient == nil {
		return "", fmt.Errorf("RPC client not configured")
	}

	// Parse ABI
	parsedABI, err := abi.JSON(strings.NewReader(string(abiJSON)))
	if err != nil {
		return "", fmt.Errorf("failed to parse ABI: %w", err)
	}

	// Pack data
	data, err := parsedABI.Pack(functionName, args...)
	if err != nil {
		return "", fmt.Errorf("failed to pack data: %w", err)
	}

	// Get chain ID
	chainID, err := s.ethClient.ChainID(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get chain ID: %w", err)
	}

	// Get nonce
	nonce, err := s.ethClient.PendingNonceAt(ctx, s.address)
	if err != nil {
		return "", fmt.Errorf("failed to get nonce: %w", err)
	}

	// Get gas price
	gasPrice, err := s.ethClient.SuggestGasPrice(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get gas price: %w", err)
	}

	// Estimate gas
	to := common.HexToAddress(contractAddress)
	msg := ethereum.CallMsg{
		From: s.address,
		To:   &to,
		Data: data,
	}
	gasLimit, err := s.ethClient.EstimateGas(ctx, msg)
	if err != nil {
		// Fallback for gas estimation failure (or add buffer)
		gasLimit = 300000 // Safe default for simple calls
	} else {
		gasLimit = uint64(float64(gasLimit) * 1.2) // Add buffer
	}

	// Create transaction (Legacy for simplicity, or EIP-1559 if supported)
	// Using NewTransaction (Legacy) is safest for generic support unless we check feecap
	tx := types.NewTransaction(nonce, to, big.NewInt(0), gasLimit, gasPrice, data)

	// Sign transaction
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), s.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %w", err)
	}

	// Send transaction
	err = s.ethClient.SendTransaction(ctx, signedTx)
	if err != nil {
		return "", fmt.Errorf("failed to send transaction: %w", err)
	}

	return signedTx.Hash().Hex(), nil
}

// WaitForTransactionReceipt waits for a transaction to be mined
func (s *ClientSigner) WaitForTransactionReceipt(ctx context.Context, txHash string) (*x402evm.TransactionReceipt, error) {
	if s.ethClient == nil {
		return nil, fmt.Errorf("RPC client not configured")
	}

	hash := common.HexToHash(txHash)

	// Polling loop
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			receipt, err := s.ethClient.TransactionReceipt(ctx, hash)
			if err != nil {
				if err == ethereum.NotFound {
					continue // Not mined yet
				}
				return nil, err
			}
			return &x402evm.TransactionReceipt{
				Status:      receipt.Status,
				BlockNumber: receipt.BlockNumber.Uint64(),
				TxHash:      receipt.TxHash.Hex(),
			}, nil
		}
	}
}
