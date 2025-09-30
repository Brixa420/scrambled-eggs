// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Memory Management Contract
 * @dev Handles storage, validation, and dispute resolution for memory claims
 */
contract MemoryManagement {
    // Struct to represent a memory claim
    struct MemoryClaim {
        address owner;
        string contentHash; // IPFS or similar content-addressable storage hash
        uint256 timestamp;
        uint256 stakeAmount;
        bool isDisputed;
        bool isValid;
        uint256 verificationThreshold;
        uint256 verificationCount;
        mapping(address => bool) verifiers;
        mapping(address => bool) disputers;
    }

    // Contract state
    address public owner;
    uint256 public minimumStake;
    uint256 public disputePeriod; // in seconds
    
    // Mappings
    mapping(bytes32 => MemoryClaim) public memoryClaims;
    mapping(address => uint256) public reputationScores;
    mapping(address => uint256) public stakedAmounts;
    
    // Events
    event MemoryClaimed(
        bytes32 indexed claimId,
        address indexed owner,
        string contentHash,
        uint256 timestamp
    );
    
    event MemoryVerified(
        bytes32 indexed claimId,
        address indexed verifier,
        bool isValid
    );
    
    event DisputeRaised(
        bytes32 indexed claimId,
        address indexed disputer,
        string reason
    );
    
    event DisputeResolved(
        bytes32 indexed claimId,
        bool claimUpheld,
        address[] rewardedVerifiers,
        address[] penalizedVerifiers
    );

    // Modifiers
    modifier onlyOwner() {
        require(msg.sender == owner, "Not contract owner");
        _;
    }
    
    modifier validClaim(bytes32 claimId) {
        require(memoryClaims[claimId].owner != address(0), "Invalid claim ID");
        _;
    }

    constructor(uint256 _minimumStake, uint256 _disputePeriod) {
        owner = msg.sender;
        minimumStake = _minimumStake;
        disputePeriod = _disputePeriod;
    }

    /**
     * @dev Submit a new memory claim
     * @param contentHash The content-addressable hash of the memory content
     * @param verificationThreshold Number of verifications required
     */
    function submitMemoryClaim(
        string calldata contentHash,
        uint256 verificationThreshold
    ) external payable {
        require(msg.value >= minimumStake, "Insufficient stake");
        require(bytes(contentHash).length > 0, "Empty content hash");
        require(verificationThreshold > 0, "Invalid verification threshold");
        
        bytes32 claimId = keccak256(abi.encodePacked(
            msg.sender,
            contentHash,
            block.timestamp
        ));
        
        require(memoryClaims[claimId].owner == address(0), "Claim already exists");
        
        MemoryClaim storage newClaim = memoryClaims[claimId];
        newClaim.owner = msg.sender;
        newClaim.contentHash = contentHash;
        newClaim.timestamp = block.timestamp;
        newClaim.stakeAmount = msg.value;
        newClaim.verificationThreshold = verificationThreshold;
        newClaim.isDisputed = false;
        newClaim.isValid = true;
        
        stakedAmounts[msg.sender] += msg.value;
        
        emit MemoryClaimed(claimId, msg.sender, contentHash, block.timestamp);
    }

    /**
     * @dev Verify a memory claim
     * @param claimId The ID of the claim to verify
     * @param isValid Whether the verifier believes the claim is valid
     */
    function verifyMemory(bytes32 claimId, bool isValid) 
        external 
        validClaim(claimId) 
    {
        MemoryClaim storage claim = memoryClaims[claimId];
        
        require(msg.sender != claim.owner, "Cannot verify own claim");
        require(!claim.verifiers[msg.sender], "Already verified");
        require(!claim.isDisputed, "Claim is under dispute");
        require(claim.isValid, "Claim already invalidated");
        
        claim.verifiers[msg.sender] = true;
        
        if (isValid) {
            claim.verificationCount++;
            
            // Update reputation for successful verification
            if (claim.verificationCount >= claim.verificationThreshold) {
                reputationScores[claim.owner] += 1;
                
                // Distribute staked amount to verifiers
                uint256 rewardPerVerifier = claim.stakeAmount / claim.verificationCount;
                
                // This is a simplified version - in production, you'd need to track verifiers
                // and distribute rewards accordingly
                payable(msg.sender).transfer(rewardPerVerifier);
            }
        } else {
            // If verification fails, initiate dispute
            _initiateDispute(claimId, "Verification failed");
        }
        
        emit MemoryVerified(claimId, msg.sender, isValid);
    }

    /**
     * @dev Raise a dispute about a memory claim
     * @param claimId The ID of the claim to dispute
     * @param reason The reason for the dispute
     */
    function raiseDispute(bytes32 claimId, string calldata reason) 
        external 
        payable 
        validClaim(claimId) 
    {
        require(msg.value >= minimumStake, "Insufficient dispute stake");
        require(!memoryClaims[claimId].isDisputed, "Dispute already raised");
        
        _initiateDispute(claimId, reason);
    }
    
    /**
     * @dev Internal function to handle dispute initiation
     */
    function _initiateDispute(bytes32 claimId, string memory reason) internal {
        MemoryClaim storage claim = memoryClaims[claimId];
        
        claim.isDisputed = true;
        claim.disputers[msg.sender] = true;
        
        // In a real implementation, this would trigger an off-chain dispute resolution process
        // and the result would be submitted via resolveDispute
        
        emit DisputeRaised(claimId, msg.sender, reason);
    }
    
    /**
     * @dev Resolve a dispute (callable by owner/oracle in production)
     * @param claimId The ID of the disputed claim
     * @param claimUpheld Whether the original claim is valid
     * @param rewardedVerifiers Addresses of verifiers who were correct
     * @param penalizedVerifiers Addresses of verifiers who were incorrect
     */
    function resolveDispute(
        bytes32 claimId,
        bool claimUpheld,
        address[] calldata rewardedVerifiers,
        address[] calldata penalizedVerifiers
    ) external onlyOwner validClaim(claimId) {
        MemoryClaim storage claim = memoryClaims[claimId];
        
        require(claim.isDisputed, "No active dispute");
        
        // Distribute rewards and penalties
        if (claimUpheld) {
            // Original claim was valid
            reputationScores[claim.owner] += 2;
            
            // Reward verifiers who supported the claim
            for (uint i = 0; i < rewardedVerifiers.length; i++) {
                if (claim.verifiers[rewardedVerifiers[i]]) {
                    reputationScores[rewardedVerifiers[i]] += 1;
                    // In a real implementation, distribute staked amounts
                }
            }
        } else {
            // Original claim was invalid
            if (reputationScores[claim.owner] > 0) {
                reputationScores[claim.owner] -= 1;
            }
            
            // Penalize verifiers who supported the invalid claim
            for (uint i = 0; i < penalizedVerifiers.length; i++) {
                if (reputationScores[penalizedVerifiers[i]] > 0) {
                    reputationScores[penalizedVerifiers[i]] -= 1;
                }
            }
            
            // Mark claim as invalid
            claim.isValid = false;
            
            // In a real implementation, distribute staked amounts to disputers
        }
        
        emit DisputeResolved(
            claimId,
            claimUpheld,
            rewardedVerifiers,
            penalizedVerifiers
        );
    }
    
    /**
     * @dev Get verification status of a claim
     * @param claimId The ID of the claim
     * @return verified Whether the claim is verified
     * @return verificationCount Current verification count
     * @return threshold Verification threshold
     * @return disputed Whether the claim is under dispute
     */
    function getVerificationStatus(bytes32 claimId)
        external
        view
        validClaim(claimId)
        returns (
            bool verified,
            uint256 verificationCount,
            uint256 threshold,
            bool disputed
        )
    {
        MemoryClaim storage claim = memoryClaims[claimId];
        return (
            claim.verificationCount >= claim.verificationThreshold,
            claim.verificationCount,
            claim.verificationThreshold,
            claim.isDisputed
        );
    }
    
    /**
     * @dev Update minimum stake required for claims
     * @param newStake The new minimum stake amount
     */
    function setMinimumStake(uint256 newStake) external onlyOwner {
        minimumStake = newStake;
    }
    
    /**
     * @dev Update dispute period
     * @param newPeriod The new dispute period in seconds
     */
    function setDisputePeriod(uint256 newPeriod) external onlyOwner {
        disputePeriod = newPeriod;
    }
    
    /**
     * @dev Withdraw staked funds (after dispute resolution)
     * @param amount The amount to withdraw
     */
    function withdrawStake(uint256 amount) external {
        require(stakedAmounts[msg.sender] >= amount, "Insufficient balance");
        
        stakedAmounts[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
    
    // Fallback function to accept ETH
    receive() external payable {}
}
