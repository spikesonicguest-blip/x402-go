package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	x402 "x402-go"
	x402http "x402-go/http"
	"x402-go/mechanisms/evm"
	evmclient "x402-go/mechanisms/evm/exact/client"
	evmsigners "x402-go/signers/evm"

	"github.com/joho/godotenv"
)

/**
 * ERC-20 Authorization Example (Non-EIP-3009)
 *
 * This example demonstrates how x402 handles payments with standard ERC-20 tokens
 * that do not support EIP-3009 transferWithAuthorization.
 *
 * The flow involves:
 * 1. Automatic detection that EIP-3009 is not supported
 * 2. Checking on-chain allowance
 * 3. Sending an 'approve' transaction if allowance is insufficient
 * 4. Waiting for the approve transaction to be mined
 * 5. Signing the payment authorization
 * 6. Sending the payment request
 */

func init() {
	// SIMULATION: Force USDC to be treated as non-EIP-3009 for this example
	// This forces the library to use the standard ERC-20 'approve' flow
	config := evm.NetworkConfigs["eip155:84532"] // Base Sepolia

	// Create a copy of the asset info but with SupportsEIP3009 = false
	usdcInfo := config.SupportedAssets["USDC"]
	usdcInfo.SupportsEIP3009 = false

	// Update the map
	config.SupportedAssets["USDC"] = usdcInfo
	config.DefaultAsset = usdcInfo
	evm.NetworkConfigs["eip155:84532"] = config

	fmt.Println("🔧 Configured USDC on Base Sepolia to verify via standard ERC-20 flow (SupportsEIP3009=false)")
}

func main() {
	// Load .env
	godotenv.Load()

	evmPrivateKey := os.Getenv("EVM_PRIVATE_KEY")
	if evmPrivateKey == "" {
		fmt.Println("❌ EVM_PRIVATE_KEY environment variable is required")
		os.Exit(1)
	}

	rpcURL := os.Getenv("RPC_URL")
	if rpcURL == "" {
		rpcURL = "https://sepolia.base.org" // Default
	}

	serverURL := os.Getenv("SERVER_URL")
	if serverURL == "" {
		serverURL = "http://localhost:4021/weather"
	}

	// Create signer
	signer, err := evmsigners.NewClientSignerFromPrivateKey(evmPrivateKey)
	if err != nil {
		fmt.Printf("❌ Failed to create signer: %v\n", err)
		os.Exit(1)
	}

	// Connect to RPC (required for checking allowance and sending transactions)
	if clientSigner, ok := signer.(*evmsigners.ClientSigner); ok {
		if err := clientSigner.Connect(rpcURL); err != nil {
			fmt.Printf("❌ Failed to connect to RPC: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("❌ Signer is not of type *ClientSigner, cannot connect to RPC")
		os.Exit(1)
	}

	fmt.Printf("📝 Signer address: %s\n", signer.Address())

	// Create x402 client
	client := x402.Newx402Client().
		Register("eip155:*", evmclient.NewExactEvmScheme(signer))

	httpClient := x402http.Newx402HTTPClient(client)

	// Make request
	ctx := context.Background()
	fmt.Printf("🌐 Making request to: %s\n", serverURL)

	req, err := http.NewRequestWithContext(ctx, "GET", serverURL, nil)
	if err != nil {
		fmt.Printf("❌ Failed to create request: %v\n", err)
		os.Exit(1)
	}

	start := time.Now()
	resp, err := httpClient.DoWithPayment(ctx, req)
	duration := time.Since(start)

	if err != nil {
		fmt.Printf("❌ Request failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	// Parse response
	var data interface{}
	json.NewDecoder(resp.Body).Decode(&data)

	// Print result
	pretty, _ := json.MarshalIndent(data, "  ", "  ")
	fmt.Printf("\n✅ Response received (Status: %d, Time: %v):\n", resp.StatusCode, duration)
	fmt.Printf("  %s\n", string(pretty))
}
