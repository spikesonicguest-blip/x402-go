package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/gagliardetto/solana-go"
	"github.com/stretchr/testify/require"
)

// Paths to components relative to this test file
const (
	clientPath      = "../../e2e/clients/go-http"
	serverPath      = "../../e2e/servers/gin"
	facilitatorPath = "../../e2e/facilitators/go"
	contractsPath   = "contracts" // Relative to this test file
)

// Config
const (
	serverPort      = "4021"
	facilitatorPort = "4022"
	anvilPort       = "8546"
	anvilChainID    = "84532" // Base Sepolia ChainID mimic

	// Anvil Account 0
	deployerKey = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
)

func TestE2E_FullFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	// 1. Build Binaries
	tmpDir := t.TempDir()
	clientBin := filepath.Join(tmpDir, "client")
	serverBin := filepath.Join(tmpDir, "server")
	facilitatorBin := filepath.Join(tmpDir, "facilitator")

	t.Log("Building binaries...")
	buildBinary(t, clientPath, clientBin)
	buildBinary(t, serverPath, serverBin)
	buildBinary(t, facilitatorPath, facilitatorBin)

	// 2. Start Anvil (Local Chain)
	t.Log("Starting Anvil...")
	anvilCmd := exec.Command("anvil", "--port", anvilPort, "--chain-id", anvilChainID, "--host", "127.0.0.1")
	anvilCmd.Env = os.Environ()
	// Unset proxy for anvil
	anvilCmd.Env = filterEnv(anvilCmd.Env, "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")
	anvilCmd.Stdout = os.Stdout
	anvilCmd.Stderr = os.Stderr
	require.NoError(t, anvilCmd.Start(), "Failed to start anvil")
	defer func() {
		_ = anvilCmd.Process.Kill()
	}()

	// Wait for Anvil
	require.Eventually(t, func() bool {
		conn, err := net.Dial("tcp", "127.0.0.1:"+anvilPort)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	}, 30*time.Second, 1*time.Second, "Anvil failed to start")

	// 3. Compile Contracts
	t.Log("Compiling contracts...")
	compileContracts(t, contractsPath)

	// 4. Deploy & Setup
	ctx := context.Background()
	client, err := ethclient.Dial("http://127.0.0.1:" + anvilPort)
	require.NoError(t, err)

	// Deploy contracts
	mockUSDCAddr, mockUSDCABI := deployContract(t, ctx, client, "MockUSDC")
	t.Logf("Deployed MockUSDC at: %s", mockUSDCAddr.Hex())

	mockFacilitatorAddr, _ := deployContract(t, ctx, client, "MockFacilitator")
	t.Logf("Deployed MockFacilitator at: %s", mockFacilitatorAddr.Hex())

	// Mint and Approve
	deployerPK, _ := crypto.HexToECDSA(strings.TrimPrefix(deployerKey, "0x"))
	deployerAddr := crypto.PubkeyToAddress(deployerPK.PublicKey)

	// Mint 1000 USDC (1,000,000 units)
	amount := big.NewInt(1000000)
	txData, err := mockUSDCABI.Pack("mint", deployerAddr, amount)
	require.NoError(t, err)
	sendTx(t, ctx, client, mockUSDCAddr, txData)

	// Approve Facilitator
	txData, err = mockUSDCABI.Pack("approve", mockFacilitatorAddr, amount)
	require.NoError(t, err)
	sendTx(t, ctx, client, mockUSDCAddr, txData)

	// 5. Setup Environment & Run Components

	// Generate random SVM key to avoid crash (not used for this specific EVM test flow)
	svmKey, err := solana.NewRandomPrivateKey()
	require.NoError(t, err)

	env := filterEnv(os.Environ(), "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")
	env = append(env,
		fmt.Sprintf("EVM_PRIVATE_KEY=%s", strings.TrimPrefix(deployerKey, "0x")),
		fmt.Sprintf("SVM_PRIVATE_KEY=%s", svmKey.String()),

		fmt.Sprintf("EVM_RPC_URL=http://127.0.0.1:%s", anvilPort),
		fmt.Sprintf("EVM_FACILITATOR_CONTRACT_ADDRESS=%s", mockFacilitatorAddr.Hex()),
		fmt.Sprintf("EVM_USDC_ADDRESS=%s", mockUSDCAddr.Hex()),
	)

	// 6. Start Facilitator
	t.Log("Starting Facilitator...")
	facilitatorCmd := exec.Command(facilitatorBin)
	facilitatorCmd.Env = append(env, fmt.Sprintf("PORT=%s", facilitatorPort))
	facilitatorCmd.Stdout = os.Stdout
	facilitatorCmd.Stderr = os.Stderr
	require.NoError(t, facilitatorCmd.Start())
	defer func() { _ = facilitatorCmd.Process.Kill() }()
	time.Sleep(2 * time.Second)

	// 7. Start Server
	t.Log("Starting Server...")
	serverCmd := exec.Command(serverBin)
	serverCmd.Env = append(env,
		fmt.Sprintf("PORT=%s", serverPort),
		fmt.Sprintf("FACILITATOR_URL=http://localhost:%s", facilitatorPort),
		fmt.Sprintf("EVM_PAYEE_ADDRESS=%s", deployerAddr.Hex()),
		"SVM_PAYEE_ADDRESS=MockSvmAddress111111111111111111111111111111",
	)
	serverCmd.Stdout = os.Stdout
	serverCmd.Stderr = os.Stderr
	require.NoError(t, serverCmd.Start())
	defer func() {
		_ = serverCmd.Process.Signal(os.Interrupt)
		time.Sleep(500 * time.Millisecond)
		_ = serverCmd.Process.Kill()
	}()
	time.Sleep(2 * time.Second)

	// 8. Run Client
	t.Run("Case: EVM Payment Success (Local Chain)", func(t *testing.T) {
		clientCmd := exec.Command(clientBin)
		clientCmd.Env = append(env,
			fmt.Sprintf("RESOURCE_SERVER_URL=http://localhost:%s", serverPort),
			"ENDPOINT_PATH=/protected",
		)

		output, err := clientCmd.CombinedOutput()
		t.Logf("Client Output: %s", string(output))

		require.NoError(t, err, "Client failed to run")

		var result struct {
			Success bool   `json:"success"`
			Error   string `json:"error"`
		}
		jsonStr := extractJSON(string(output))
		err = json.Unmarshal([]byte(jsonStr), &result)
		require.NoError(t, err, "Failed to parse client output: %s", jsonStr)

		if !result.Success {
			t.Fatalf("Payment flow failed: %s", result.Error)
		}
		t.Log("✅ Payment flow succeeded with on-chain settlement!")
	})
}

// Helpers

func filterEnv(env []string, keys ...string) []string {
	var filtered []string
	keyMap := make(map[string]bool)
	for _, k := range keys {
		keyMap[k] = true
	}

	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) > 0 && keyMap[parts[0]] {
			continue
		}
		filtered = append(filtered, e)
	}
	return filtered
}

func buildBinary(t *testing.T, srcPath, destPath string) {
	cmd := exec.Command("go", "build", "-o", destPath, ".")
	cmd.Dir = srcPath
	cmd.Env = append(filterEnv(os.Environ(), "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"), "CGO_ENABLED=1")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "Build failed for %s: %s", srcPath, string(out))
}

func compileContracts(t *testing.T, contractsPath string) {
	cmd := exec.Command("forge", "build")
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "Forge build failed: %s", string(out))
}

type Artifact struct {
	ABI      json.RawMessage `json:"abi"`
	Bytecode struct {
		Object string `json:"object"`
	} `json:"bytecode"`
}

func deployContract(t *testing.T, ctx context.Context, client *ethclient.Client, contractName string) (common.Address, abi.ABI) {
	// Read artifact
	// Try root/out first (if CWD is root), then ../../out (if CWD is test/e2e)
	base := "out"
	if _, err := os.Stat(base); os.IsNotExist(err) {
		base = "../../out"
	}

	path := fmt.Sprintf("%s/MockContracts.sol/%s.json", base, contractName)
	data, err := os.ReadFile(path)

	// Fallback to absolute path search if still fails?
	if err != nil {
		wd, _ := os.Getwd()
		t.Logf("CWD: %s, Tried path: %s", wd, path)
		require.NoError(t, err, "Read artifact failed")
	}

	var artifact Artifact
	err = json.Unmarshal(data, &artifact)
	require.NoError(t, err)

	parsedABI, err := abi.JSON(strings.NewReader(string(artifact.ABI)))
	require.NoError(t, err)

	bytecode := common.FromHex(artifact.Bytecode.Object)

	// Sign and Send
	privateKey, _ := crypto.HexToECDSA(strings.TrimPrefix(deployerKey, "0x"))
	chainID, _ := client.ChainID(ctx)
	from := crypto.PubkeyToAddress(privateKey.PublicKey)

	nonce, _ := client.PendingNonceAt(ctx, from)
	gasPrice, _ := client.SuggestGasPrice(ctx)

	gasLimit := uint64(3000000)

	tx := types.NewContractCreation(nonce, big.NewInt(0), gasLimit, gasPrice, bytecode)
	signedTx, _ := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)

	err = client.SendTransaction(ctx, signedTx)
	require.NoError(t, err)

	// Wait for receipt
	waitForReceipt(t, ctx, client, signedTx.Hash())

	return crypto.CreateAddress(from, nonce), parsedABI
}

func sendTx(t *testing.T, ctx context.Context, client *ethclient.Client, to common.Address, data []byte) {
	privateKey, _ := crypto.HexToECDSA(strings.TrimPrefix(deployerKey, "0x"))
	chainID, _ := client.ChainID(ctx)
	from := crypto.PubkeyToAddress(privateKey.PublicKey)

	nonce, _ := client.PendingNonceAt(ctx, from)
	gasPrice, _ := client.SuggestGasPrice(ctx)

	gasLimit := uint64(200000)

	tx := types.NewTransaction(nonce, to, big.NewInt(0), gasLimit, gasPrice, data)
	signedTx, _ := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)

	err := client.SendTransaction(ctx, signedTx)
	require.NoError(t, err)
	waitForReceipt(t, ctx, client, signedTx.Hash())
}

func waitForReceipt(t *testing.T, ctx context.Context, client *ethclient.Client, hash common.Hash) {
	for i := 0; i < 30; i++ {
		receipt, err := client.TransactionReceipt(ctx, hash)
		if err == nil && receipt != nil && receipt.Status == types.ReceiptStatusSuccessful {
			return
		}
		if err != nil && err.Error() != "not found" {
			t.Logf("Error getting receipt for %s: %v", hash.Hex(), err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("Transaction receipt timeout or failed for hash: %s", hash.Hex())
}

func extractJSON(s string) string {
	start := strings.Index(s, "{")
	if start == -1 {
		return s
	}
	end := strings.LastIndex(s, "}")
	if end == -1 {
		return s
	}
	return s[start : end+1]
}
