/**
 * x402 Client with ERC-20 Support (Browser/Frontend)
 * 
 * This example demonstrates how to implement an x402 client in TypeScript
 * that handles both EIP-3009 and standard ERC-20 tokens.
 * 
 * Dependencies:
 * - ethers (v6) or viem
 */

import { ethers, BrowserProvider, Contract } from 'ethers';

// Configuration
const FACILITATOR_ADDRESS = "0x555e3311a9893c9B17444C1Ff0d88192a57Ef13e";

// ABIs
const ERC20_ABI = [
    "function allowance(address owner, address spender) view returns (uint256)",
    "function approve(address spender, uint256 amount) returns (bool)",
    "function name() view returns (string)",
    "function version() view returns (string)",
    "function nonces(address owner) view returns (bytes32)" // EIP-3009 nonce
];

// EIP-712 Types
const EIP712_DOMAIN = [
    { name: "name", type: "string" },
    { name: "version", type: "string" },
    { name: "chainId", type: "uint256" },
    { name: "verifyingContract", type: "address" }
];

const TRANSFER_WITH_AUTHORIZATION_TYPE = [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" }
];

const TOKEN_TRANSFER_WITH_AUTHORIZATION_TYPE = [
    { name: "token", type: "address" },
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
    { name: "needApprove", type: "bool" }
];

interface PaymentRequirements {
    scheme: string;
    payTo: string;
    amount: string; // wei
    asset: string; // token address
    network: string; // eip155:chainId
    extra?: Record<string, any>;
}

export class X402Client {
    private provider: BrowserProvider;
    private signer: ethers.JsonRpcSigner;

    constructor(provider: BrowserProvider, signer: ethers.JsonRpcSigner) {
        this.provider = provider;
        this.signer = signer;
    }

    /**
     * Handles a 402 Payment Required response
     */
    async handlePaymentRequired(response: Response): Promise<Response> {
        if (response.status !== 402) return response;

        // 1. Get requirements
        const header = response.headers.get("PAYMENT-REQUIRED");
        if (!header) throw new Error("Missing PAYMENT-REQUIRED header");

        const requirements = JSON.parse(atob(header));
        // Select first supported requirement (assuming EVM exact)
        const req = requirements.accepts[0]; // Simplified selection

        // 2. Create payload
        const payload = await this.createPaymentPayload(req);

        // 3. Retry request
        const paymentHeader = btoa(JSON.stringify(payload));
        const newHeaders = new Headers(response.headers);
        newHeaders.set("PAYMENT-SIGNATURE", paymentHeader);

        // Clone request with new headers (implementation depends on context)
        // Here assuming we just return the payload header for the caller to retry
        return new Response(null, { headers: { "PAYMENT-SIGNATURE": paymentHeader } });
    }

    /**
     * Creates a payment payload (handling ERC-20 approval if needed)
     */
    async createPaymentPayload(req: PaymentRequirements): Promise<any> {
        const chainId = (await this.provider.getNetwork()).chainId;
        const userAddress = await this.signer.getAddress();

        // Setup token contract
        const token = new Contract(req.asset, ERC20_ABI, this.signer);

        // Check EIP-3009 support (simplified check)
        let supportsEIP3009 = false;
        try {
            // Try to call a 3009 function or check configuration
            // Here we assume false for generic ERC-20 or check a list
            // For robust check, try-call nonce function?
            await token.nonces(userAddress);
            supportsEIP3009 = true;
        } catch (e) {
            supportsEIP3009 = false;
        }

        // Generate nonce
        const nonce = ethers.hexlify(ethers.randomBytes(32));
        const validAfter = 0;
        const validBefore = Math.floor(Date.now() / 1000) + 3600;

        if (supportsEIP3009) {
            // --- EIP-3009 Flow ---
            const domain = {
                name: await token.name(),
                version: await token.version(),
                chainId: chainId,
                verifyingContract: req.asset
            };

            const message = {
                from: userAddress,
                to: req.payTo,
                value: req.amount,
                validAfter,
                validBefore,
                nonce
            };

            const signature = await this.signer.signTypedData(
                domain,
                { TransferWithAuthorization: TRANSFER_WITH_AUTHORIZATION_TYPE },
                message
            );

            return {
                x402Version: 2,
                payload: {
                    type: "authorizationEip3009",
                    authorization: message,
                    signature
                }
            };
        } else {
            // --- Standard ERC-20 Flow ---

            // 1. Check Allowance
            const allowance = await token.allowance(userAddress, FACILITATOR_ADDRESS);
            if (BigInt(allowance) < BigInt(req.amount)) {
                console.log("Approving token...");
                const tx = await token.approve(FACILITATOR_ADDRESS, req.amount);
                await tx.wait(); // Wait for mining
                console.log("Approved.");
            }

            // 2. Sign Authorization (against Facilitator)
            const domain = {
                name: "Facilitator",
                version: "1",
                chainId: chainId,
                verifyingContract: FACILITATOR_ADDRESS
            };

            const message = {
                token: req.asset,
                from: userAddress,
                to: req.payTo,
                value: req.amount,
                validAfter,
                validBefore,
                nonce,
                needApprove: true
            };

            const signature = await this.signer.signTypedData(
                domain,
                { tokenTransferWithAuthorization: TOKEN_TRANSFER_WITH_AUTHORIZATION_TYPE },
                message
            );

            return {
                x402Version: 2,
                payload: {
                    type: "authorization",
                    authorization: message,
                    signature
                }
            };
        }
    }
}
