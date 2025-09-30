// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./MemoryManagement.sol";

/**
 * @title Memory Verification
 * @dev Handles the verification of memory claims by peers
 */
contract MemoryVerification {
    // Reference to the main MemoryManagement contract
    MemoryManagement public memoryManagement;
    
    // Verification parameters
    uint256 public verificationReward; // Reward for successful verification
    uint256 public verificationStake; // Required stake to verify
    uint256 public verificationThreshold; // Minimum verifications required
    uint256 public verificationWindow; // Time window for verifications (in seconds)
    
    // Verification tracking
    struct Verification {
        address verifier;
        bool isValid;
        uint256 timestamp;
    }
    
    mapping(bytes32 => Verification[]) public verifications;
    mapping(address => uint256) public verifierStakes;
    
    // Events
    event VerificationSubmitted(
        bytes32 indexed claimId,
        address indexed verifier,
        bool isValid,
        uint256 timestamp
    );
    
    event VerificationRewardClaimed(
        address indexed verifier,
        uint256 amount
    );
    
    // Modifiers
    modifier onlyMemoryManagement() {
        require(
            msg.sender == address(memoryManagement),
            "Caller is not MemoryManagement contract"
        );
        _;
    }
    
    constructor(
        address _memoryManagementAddress,
        uint256 _verificationReward,
        uint256 _verificationStake,
        uint256 _verificationThreshold,
        uint256 _verificationWindow
    ) {
        memoryManagement = MemoryManagement(_memoryManagementAddress);
        verificationReward = _verificationReward;
        verificationStake = _verificationStake;
        verificationThreshold = _verificationThreshold;
        verificationWindow = _verificationWindow;
    }
    
    /**
     * @dev Stake tokens to become a verifier
     */
    function stakeForVerification() external payable {
        require(msg.value >= verificationStake, "Insufficient stake");
        verifierStakes[msg.sender] += msg.value;
    }
    
    /**
     * @dev Submit a verification for a memory claim
     * @param claimId The ID of the claim to verify
     * @param isValid Whether the verifier believes the claim is valid
     */
    function submitVerification(
        bytes32 claimId,
        bool isValid
    ) external {
        require(
            verifierStakes[msg.sender] >= verificationStake,
            "Insufficient stake to verify"
        );
        
        // Check if already verified by this address
        for (uint256 i = 0; i < verifications[claimId].length; i++) {
            require(
                verifications[claimId][i].verifier != msg.sender,
                "Already verified this claim"
            );
        }
        
        // Record verification
        verifications[claimId].push(Verification({
            verifier: msg.sender,
            isValid: isValid,
            timestamp: block.timestamp
        }));
        
        emit VerificationSubmitted(claimId, msg.sender, isValid, block.timestamp);
        
        // If enough verifications, trigger resolution in MemoryManagement
        if (verifications[claimId].length >= verificationThreshold) {
            _resolveVerifications(claimId);
        }
    }
    
    /**
     * @dev Resolve verifications for a claim
     */
    function _resolveVerifications(bytes32 claimId) internal {
        uint256 validCount = 0;
        uint256 invalidCount = 0;
        
        // Count valid and invalid verifications
        for (uint256 i = 0; i < verifications[claimId].length; i++) {
            if (verifications[claimId][i].isValid) {
                validCount++;
            } else {
                invalidCount++;
            }
        }
        
        // Notify MemoryManagement of the result
        if (validCount >= verificationThreshold) {
            memoryManagement.verifyMemory(claimId, true);
        } else if (invalidCount >= verificationThreshold) {
            memoryManagement.verifyMemory(claimId, false);
        }
        
        // Distribute rewards to verifiers who agreed with the majority
        bool majorityValid = validCount >= invalidCount;
        
        for (uint256 i = 0; i < verifications[claimId].length; i++) {
            if (verifications[claimId][i].isValid == majorityValid) {
                // Reward verifier (in a real implementation, transfer tokens)
                // payable(verifications[claimId][i].verifier).transfer(verificationReward);
            }
        }
    }
    
    /**
     * @dev Claim verification rewards
     */
    function claimRewards() external {
        // In a real implementation, track and distribute rewards
        // This is a simplified version
        uint256 rewardAmount = 0; // Calculate based on successful verifications
        
        require(rewardAmount > 0, "No rewards to claim");
        
        // Reset reward counter
        // rewards[msg.sender] = 0;
        
        // Transfer reward
        payable(msg.sender).transfer(rewardAmount);
        
        emit VerificationRewardClaimed(msg.sender, rewardAmount);
    }
    
    /**
     * @dev Get verification status for a claim
     */
    function getVerificationStatus(bytes32 claimId)
        external
        view
        returns (
            uint256 totalVerifications,
            uint256 validVerifications,
            uint256 invalidVerifications,
            bool isVerified
        )
    {
        totalVerifications = verifications[claimId].length;
        
        for (uint256 i = 0; i < totalVerifications; i++) {
            if (verifications[claimId][i].isValid) {
                validVerifications++;
            } else {
                invalidVerifications++;
            }
        }
        
        isVerified = (validVerifications >= verificationThreshold) || 
                    (invalidVerifications >= verificationThreshold);
                    
        return (
            totalVerifications,
            validVerifications,
            invalidVerifications,
            isVerified
        );
    }
    
    /**
     * @dev Update verification parameters
     */
    function updateVerificationParameters(
        uint256 _verificationReward,
        uint256 _verificationStake,
        uint256 _verificationThreshold,
        uint256 _verificationWindow
    ) external {
        verificationReward = _verificationReward;
        verificationStake = _verificationStake;
        verificationThreshold = _verificationThreshold;
        verificationWindow = _verificationWindow;
    }
    
    // Fallback function to accept ETH
    receive() external payable {}
}
