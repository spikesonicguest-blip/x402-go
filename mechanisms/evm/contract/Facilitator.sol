//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IEIP3009, IEIP3009Bytes} from "./IEIP3009.sol";

contract Facilitator is Initializable, OwnableUpgradeable, PausableUpgradeable, EIP712Upgradeable {
    using SafeERC20 for IERC20;

    // bytes32 public constant TOKEN_TRANSFER_WITH_AUTHORIZATION_TYPEHASH =
    //     keccak256(
    //         "tokenTransferWithAuthorization(address token,address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce,bool needApprove)"
    //     );
    bytes32 public constant TOKEN_TRANSFER_WITH_AUTHORIZATION_TYPEHASH =
        0xefef239b7949d870353c6e75dcc83be6364695aee0e3b5cdcc4ce3971a2a26a0;

    // bytes32 public constant TOKEN_CANCEL_AUTHORIZATION_TYPEHASH =
    //     keccak256("tokenCancelAuthorization(address token,address authorizer,bytes32 nonce,bool needApprove)");
    bytes32 public constant TOKEN_CANCEL_AUTHORIZATION_TYPEHASH =
        0xdbe808fc3a363cde38b857e66e7263676569e853ff086bf2ec6f9aca0b919af9;

    /*«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-*/
    /*                        CUSTOM ERRORS                       */
    /*-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»*/
    error InvalidOperator();
    error AuthorizationNotYetValid();
    error AuthorizationExpired();
    error NonceUsed();
    error InvalidCaller();
    error InvalidSignature();
    error InsufficientAllowance();
    error InvalidSignatureLength();
    error InvalidSignatureVValue();

    /*«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-«-*/
    /*                        EVENT                               */
    /*-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»-»*/
    event AuthorizationUsed(address indexed token, address indexed authorizer, bytes32 indexed nonce);
    event AuthorizationCanceled(address indexed token, address indexed authorizer, bytes32 indexed nonce);
    event OperatorChanged(address indexed operator, bool available);

    /**
     * @dev token address =>token authorizer => nonce => bool (true if nonce is used)
     */
    mapping(address => mapping(address => mapping(bytes32 => bool))) private _authorizationStates;

    // Mapping from address to operator
    mapping(address => bool) public isOperator;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize() public initializer {
        __Ownable_init(msg.sender);
        __Pausable_init();
        __EIP712_init("Facilitator", "1");
    }

    /**
     * @dev Pauses the contract.
     */
    function pauseContract() public onlyOwner {
        _pause();
    }

    /**
     * @dev Unpauses the contract.
     */
    function unPauseContract() public onlyOwner {
        _unpause();
    }

    modifier onlyOperator() {
        if (!isOperator[msg.sender]) revert InvalidOperator();
        _;
    }

    function setOperator(address _operator, bool _available) public onlyOwner {
        isOperator[_operator] = _available;
        emit OperatorChanged(_operator, _available);
    }

    /**
     * @notice Execute a transfer with a signed authorization
     * @dev EOA wallet signatures should be packed in the order of r, s, v.
     * @param token         Token address
     * @param from          Payer's address (Authorizer)
     * @param to            Payee's address
     * @param value         Amount to be transferred
     * @param validAfter    The time after which this is valid (unix time)
     * @param validBefore   The time before which this is valid (unix time)
     * @param nonce         Unique nonce
     * @param needApprove   Whether to approve the token to the facilitator
     * @param signature     Signature bytes signed by an EOA wallet or a contract wallet
     */
    function tokenTransferWithAuthorization(
        address token,
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bool needApprove,
        bytes memory signature
    ) external whenNotPaused onlyOperator {
        _tokenTransferWithAuthorization(token, from, to, value, validAfter, validBefore, nonce, needApprove, signature);
    }

    /**
     * @notice Execute a transfer with a signed authorization
     * @param token         Token address
     * @param from          Payer's address (Authorizer)
     * @param to            Payee's address
     * @param value         Amount to be transferred
     * @param validAfter    The time after which this is valid (unix time)
     * @param validBefore   The time before which this is valid (unix time)
     * @param nonce         Unique nonce
     * @param needApprove   Whether to approve the token to the facilitator
     * @param v             v of the signature
     * @param r             r of the signature
     * @param s             s of the signature
     */
    function tokenTransferWithAuthorization(
        address token,
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bool needApprove,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external whenNotPaused onlyOperator {
        _tokenTransferWithAuthorization(
            token,
            from,
            to,
            value,
            validAfter,
            validBefore,
            nonce,
            needApprove,
            abi.encodePacked(r, s, v)
        );
    }

    function tokenVerifyTransferAuthorization(
        address token,
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bool needApprove,
        bytes memory signature
    ) public view returns (bool) {
        return
            _tokenVerifyTransferAuthorization(
                token,
                from,
                to,
                value,
                validAfter,
                validBefore,
                nonce,
                needApprove,
                signature
            );
    }

    function tokenVerifyTransferAuthorization(
        address token,
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bool needApprove,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public view returns (bool) {
        return
            _tokenVerifyTransferAuthorization(
                token,
                from,
                to,
                value,
                validAfter,
                validBefore,
                nonce,
                needApprove,
                abi.encodePacked(r, s, v)
            );
    }

    /**
     * @notice Attempt to cancel an authorization
     * @dev Works only if the authorization is not yet used.
     * EOA wallet signatures should be packed in the order of r, s, v.
     * @param token         Token address
     * @param authorizer    Authorizer's address
     * @param nonce         Nonce of the authorization
     * @param needApprove   Whether to approve the token to the facilitator
     * @param signature     Signature bytes signed by an EOA wallet or a contract wallet
     */
    function tokenCancelAuthorization(
        address token,
        address authorizer,
        bytes32 nonce,
        bool needApprove,
        bytes memory signature
    ) external whenNotPaused onlyOperator {
        _tokenCancelAuthorization(token, authorizer, nonce, needApprove, signature);
    }

    /**
     * @notice Attempt to cancel an authorization
     * @dev Works only if the authorization is not yet used.
     * @param token         Token address
     * @param authorizer    Authorizer's address
     * @param nonce         Nonce of the authorization
     * @param needApprove   Whether to approve the token to the facilitator
     * @param v             v of the signature
     * @param r             r of the signature
     * @param s             s of the signature
     */
    function tokenCancelAuthorization(
        address token,
        address authorizer,
        bytes32 nonce,
        bool needApprove,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external whenNotPaused onlyOperator {
        _tokenCancelAuthorization(token, authorizer, nonce, needApprove, abi.encodePacked(r, s, v));
    }

    function checkEIP3009(
        address token
    ) public view returns (bool hasTransfer, bool hasReceive, bool hasCancel, bool hasState) {
        bytes memory transferCalldata = abi.encodeWithSelector(
            IEIP3009.transferWithAuthorization.selector,
            address(0),
            address(0),
            uint256(0),
            uint256(0),
            uint256(0),
            bytes32(0),
            uint8(0),
            bytes32(0),
            bytes32(0)
        );
        hasTransfer = _hasFunction(token, transferCalldata);

        bytes memory receiveCalldata = abi.encodeWithSelector(
            IEIP3009.receiveWithAuthorization.selector,
            address(0),
            address(0),
            uint256(0),
            uint256(0),
            uint256(0),
            bytes32(0),
            uint8(0),
            bytes32(0),
            bytes32(0)
        );
        hasReceive = _hasFunction(token, receiveCalldata);

        bytes memory cancelCalldata = abi.encodeWithSelector(
            IEIP3009.cancelAuthorization.selector,
            address(0),
            bytes32(0),
            uint8(0),
            bytes32(0),
            bytes32(0)
        );
        hasCancel = _hasFunction(token, cancelCalldata);

        bytes memory stateCalldata = abi.encodeWithSelector(
            IEIP3009.authorizationState.selector,
            address(0),
            bytes32(0)
        );
        hasState = _hasFunction(token, stateCalldata);
    }

    function checkEIP3009Bytes(address token) public view returns (bool hasTransfer, bool hasReceive, bool hasCancel) {
        bytes memory transferCalldata = abi.encodeWithSelector(
            IEIP3009Bytes.transferWithAuthorization.selector,
            address(0),
            address(0),
            uint256(0),
            uint256(0),
            uint256(0),
            bytes32(0),
            new bytes(0)
        );
        hasTransfer = _hasFunction(token, transferCalldata);

        bytes memory receiveCalldata = abi.encodeWithSelector(
            IEIP3009Bytes.receiveWithAuthorization.selector,
            address(0),
            address(0),
            uint256(0),
            uint256(0),
            uint256(0),
            bytes32(0),
            new bytes(0)
        );
        hasReceive = _hasFunction(token, receiveCalldata);

        bytes memory cancelCalldata = abi.encodeWithSelector(
            IEIP3009Bytes.cancelAuthorization.selector,
            address(0),
            bytes32(0),
            new bytes(0)
        );
        hasCancel = _hasFunction(token, cancelCalldata);
    }

    /**
     * @notice Returns the state of an authorization
     * @dev Nonces are randomly generated 32-byte data unique to the
     * authorizer's address
     * @param token         Token address
     * @param authorizer    Authorizer's address
     * @param nonce         Nonce of the authorization
     * @return True if the nonce is used
     */
    function tokenAuthorizationState(address token, address authorizer, bytes32 nonce) external view returns (bool) {
        return _authorizationStates[token][authorizer][nonce];
    }

    function _tokenTransferWithAuthorization(
        address token,
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bool needApprove,
        bytes memory signature
    ) internal {
        if (!needApprove) {
            // Extract v, r, s from signature for EIP-3009 standard compliance
            (uint8 v, bytes32 r, bytes32 s) = _splitSignature(signature);

            // Try standard EIP-3009 interface first (v, r, s)
            try IEIP3009(token).transferWithAuthorization(from, to, value, validAfter, validBefore, nonce, v, r, s) {
                return;
            } catch {
                // Fallback to bytes signature format for backward compatibility
                IEIP3009Bytes(token).transferWithAuthorization(
                    from,
                    to,
                    value,
                    validAfter,
                    validBefore,
                    nonce,
                    signature
                );
                return;
            }
        }

        _requireValidAuthorization(token, from, nonce, validAfter, validBefore);
        _requireTokenAllowed(token, from, value);
        _requireValidSignature(
            from,
            keccak256(
                abi.encode(
                    TOKEN_TRANSFER_WITH_AUTHORIZATION_TYPEHASH,
                    token,
                    from,
                    to,
                    value,
                    validAfter,
                    validBefore,
                    nonce,
                    needApprove
                )
            ),
            signature
        );
        _markAuthorizationAsUsed(token, from, nonce);

        IERC20(token).safeTransferFrom(from, to, value);
    }

    function _tokenCancelAuthorization(
        address token,
        address authorizer,
        bytes32 nonce,
        bool needApprove,
        bytes memory signature
    ) internal {
        if (!needApprove) {
            // Extract v, r, s from signature for EIP-3009 standard compliance
            (uint8 v, bytes32 r, bytes32 s) = _splitSignature(signature);

            // Try standard EIP-3009 interface first (v, r, s)
            try IEIP3009(token).cancelAuthorization(authorizer, nonce, v, r, s) {
                return;
            } catch {
                // Fallback to bytes signature format for backward compatibility
                IEIP3009Bytes(token).cancelAuthorization(authorizer, nonce, signature);
                return;
            }
        }
        _requireUnusedAuthorization(token, authorizer, nonce);
        _requireValidSignature(
            authorizer,
            keccak256(abi.encode(TOKEN_CANCEL_AUTHORIZATION_TYPEHASH, token, authorizer, nonce, needApprove)),
            signature
        );

        _authorizationStates[token][authorizer][nonce] = true;
        emit AuthorizationCanceled(token, authorizer, nonce);
    }

    function _tokenVerifyTransferAuthorization(
        address token,
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bool needApprove,
        bytes memory signature
    ) internal view returns (bool) {
        _requireValidAuthorization(token, from, nonce, validAfter, validBefore);
        _requireTokenAllowed(token, from, value);
        _requireValidSignature(
            from,
            keccak256(
                abi.encode(
                    TOKEN_TRANSFER_WITH_AUTHORIZATION_TYPEHASH,
                    token,
                    from,
                    to,
                    value,
                    validAfter,
                    validBefore,
                    nonce,
                    needApprove
                )
            ),
            signature
        );
        return true;
    }

    function _hasFunction(address target, bytes memory data) internal view returns (bool) {
        (bool success, bytes memory returnData) = target.staticcall(data);
        // If the call succeeds, the function exists and executed successfully
        if (success) {
            return true;
        }
        // If the call fails but returns data, the function likely exists but reverted
        // If returnData.length >= 4, it's likely a custom error or revert with reason
        // If returnData.length == 0, the function likely doesn't exist (no fallback)
        // or the contract doesn't exist
        if (returnData.length > 0) {
            return true; // Function exists but execution failed
        }
        return false; // Function doesn't exist or contract doesn't exist
    }

    /**
     * @notice Validates that signature against input data struct
     * @param signer        Signer's address
     * @param dataHash      Hash of encoded data struct
     * @param signature     Signature byte array produced by an EOA wallet or a contract wallet
     */
    function _requireValidSignature(address signer, bytes32 dataHash, bytes memory signature) private view {
        if (
            !SignatureChecker.isValidSignatureNow(
                signer,
                MessageHashUtils.toTypedDataHash(_domainSeparatorV4(), dataHash),
                signature
            )
        ) revert InvalidSignature();
    }

    function _requireValidAuthorization(
        address token,
        address authorizer,
        bytes32 nonce,
        uint256 validAfter,
        uint256 validBefore
    ) private view {
        if (block.timestamp < validAfter) revert AuthorizationNotYetValid();
        if (block.timestamp > validBefore) revert AuthorizationExpired();
        _requireUnusedAuthorization(token, authorizer, nonce);
    }

    function _requireUnusedAuthorization(address token, address authorizer, bytes32 nonce) private view {
        if (_authorizationStates[token][authorizer][nonce]) revert NonceUsed();
    }

    function _requireTokenAllowed(address token, address authorizer, uint256 value) private view {
        if (IERC20(token).allowance(authorizer, address(this)) < value) revert InsufficientAllowance();
    }

    /**
     * @notice Mark an authorization as used
     * @param token         Token address
     * @param authorizer    Authorizer's address
     * @param nonce         Nonce of the authorization
     */
    function _markAuthorizationAsUsed(address token, address authorizer, bytes32 nonce) private {
        _authorizationStates[token][authorizer][nonce] = true;
        emit AuthorizationUsed(token, authorizer, nonce);
    }

    /**
     * @notice Split signature bytes into v, r, s components
     * @dev Signature must be 65 bytes long (r=32, s=32, v=1)
     * @param signature Packed signature bytes
     * @return v Recovery id
     * @return r First 32 bytes of signature
     * @return s Second 32 bytes of signature
     */
    function _splitSignature(bytes memory signature) private pure returns (uint8 v, bytes32 r, bytes32 s) {
        //require(signature.length == 65, "Invalid signature length");
        if (signature.length != 65) revert InvalidSignatureLength();

        assembly {
            // First 32 bytes after length prefix
            r := mload(add(signature, 32))
            // Second 32 bytes
            s := mload(add(signature, 64))
            // Final byte
            v := byte(0, mload(add(signature, 96)))
        }

        // Adjust v if necessary (some wallets use 0/1 instead of 27/28)
        if (v < 27) {
            v += 27;
        }

        if (v != 27 && v != 28) revert InvalidSignatureVValue();
    }
}
