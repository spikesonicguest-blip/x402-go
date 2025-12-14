// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MockUSDC {
    string public name = "USD Coin";
    string public symbol = "USDC";
    uint8 public decimals = 6;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function mint(address to, uint256 amount) public {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        return transferFrom(msg.sender, to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        if (balanceOf[from] < amount) revert("Insufficient balance");
        
        if (from != msg.sender) {
            uint256 currentAllowance = allowance[from][msg.sender];
            if (currentAllowance != type(uint256).max) {
                 if (currentAllowance < amount) revert("Insufficient allowance");
                 allowance[from][msg.sender] = currentAllowance - amount;
            }
        }
        
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) public returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }
}

contract MockFacilitator {
    event PaymentSettled(address indexed token, address indexed from, address indexed to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, bytes signature);

    // Mock settlePayment that just calls transferFrom on the token
    // It ignores signature verification for E2E speed/simplicity (verification is done off-chain by Go code)
    // In a real scenario, this would verify signature.
    function settlePayment(
        address token,
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes calldata signature
    ) external {
        // Just execute transfer - we assume signer verified it off-chain
        // Call transferFrom on token
        // Selector for transferFrom(address,address,uint256) is 0x23b872dd
        (bool success, bytes memory data) = token.call(
            abi.encodeWithSelector(0x23b872dd, from, to, value)
        );
        require(success && (data.length == 0 || abi.decode(data, (bool))), "Transfer failed");

        emit PaymentSettled(token, from, to, value, validAfter, validBefore, nonce, signature);
    }
    
    // Authorization state mock (always unused)
    function authorizationState(address /*authorizer*/, bytes32 /*nonce*/) external pure returns (bool) {
        return false;
    }
}
