// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./MemoryManagement.sol";

/**
 * @title Memory Dispute Resolution
 * @dev Handles the arbitration process for disputed memory claims
 */
contract MemoryDisputeResolution {
    // Reference to the main MemoryManagement contract
    MemoryManagement public memoryManagement;
    
    // Dispute details
    struct Dispute {
        bytes32 claimId;
        address disputer;
        string reason;
        uint256 timestamp;
        bool resolved;
        address[] jurors;
        mapping(address => bool) votes; // true = claim valid, false = claim invalid
        uint256 votesForValidity;
        uint256 votesAgainstValidity;
    }
    
    // Dispute parameters
    uint256 public jurySize;
    uint256 public minimumJurorStake;
    uint256 public disputeFee;
    uint256 public votingPeriod; // in seconds
    
    // Dispute tracking
    mapping(bytes32 => Dispute) public disputes;
    mapping(address => bool) public isJuror;
    address[] public jurorsList;
    
    // Events
    event DisputeCreated(
        bytes32 indexed disputeId,
        bytes32 indexed claimId,
        address indexed disputer,
        string reason
    );
    
    event VoteCast(
        bytes32 indexed disputeId,
        address indexed juror,
        bool supportsClaim
    );
    
    event DisputeResolved(
        bytes32 indexed disputeId,
        bool claimUpheld,
        address[] rewardedJurors,
        address[] penalizedJurors
    );
    
    // Modifiers
    modifier onlyMemoryManagement() {
        require(
            msg.sender == address(memoryManagement),
            "Caller is not MemoryManagement contract"
        );
        _;
    }
    
    modifier onlyJuror() {
        require(isJuror[msg.sender], "Caller is not a juror");
        _;
    }
    
    constructor(
        address _memoryManagementAddress,
        uint256 _jurySize,
        uint256 _minimumJurorStake,
        uint256 _disputeFee,
        uint256 _votingPeriod
    ) {
        memoryManagement = MemoryManagement(_memoryManagementAddress);
        jurySize = _jurySize;
        minimumJurorStake = _minimumJurorStake;
        disputeFee = _disputeFee;
        votingPeriod = _votingPeriod;
    }
    
    /**
     * @dev Register as a juror by staking tokens
     */
    function registerAsJuror() external payable {
        require(msg.value >= minimumJurorStake, "Insufficient stake");
        require(!isJuror[msg.sender], "Already registered as juror");
        
        isJuror[msg.sender] = true;
        jurorsList.push(msg.sender);
    }
    
    /**
     * @dev Create a new dispute (called by MemoryManagement)
     */
    function createDispute(
        bytes32 claimId,
        address disputer,
        string calldata reason
    ) external onlyMemoryManagement returns (bytes32) {
        bytes32 disputeId = keccak256(
            abi.encodePacked(claimId, disputer, block.timestamp)
        );
        
        Dispute storage newDispute = disputes[disputeId];
        newDispute.claimId = claimId;
        newDispute.disputer = disputer;
        newDispute.reason = reason;
        newDispute.timestamp = block.timestamp;
        newDispute.resolved = false;
        
        // Select random jurors
        _selectJurors(disputeId);
        
        emit DisputeCreated(disputeId, claimId, disputer, reason);
        
        return disputeId;
    }
    
    /**
     * @dev Select random jurors for a dispute
     */
    function _selectJurors(bytes32 disputeId) internal {
        require(jurorsList.length >= jurySize, "Not enough jurors available");
        
        Dispute storage dispute = disputes[disputeId];
        
        // Simple random selection (in production, use a more secure method)
        for (uint256 i = 0; i < jurySize; i++) {
            uint256 randomIndex = uint256(
                keccak256(abi.encodePacked(block.timestamp, i))
            ) % jurorsList.length;
            
            address juror = jurorsList[randomIndex];
            
            // Ensure no duplicates
            for (uint256 j = 0; j < dispute.jurors.length; j++) {
                if (dispute.jurors[j] == juror) {
                    // Skip duplicate
                    i--;
                    continue;
                }
            }
            
            dispute.jurors.push(juror);
        }
    }
    
    /**
     * @dev Cast a vote in a dispute
     * @param disputeId The ID of the dispute
     * @param supportsClaim Whether the juror supports the original claim
     */
    function castVote(bytes32 disputeId, bool supportsClaim) external onlyJuror {
        Dispute storage dispute = disputes[disputeId];
        
        require(!dispute.resolved, "Dispute already resolved");
        require(block.timestamp < dispute.timestamp + votingPeriod, "Voting period ended");
        
        // Check if sender is a juror for this dispute
        bool isJurorForDispute = false;
        for (uint256 i = 0; i < dispute.jurors.length; i++) {
            if (dispute.jurors[i] == msg.sender) {
                isJurorForDispute = true;
                break;
            }
        }
        require(isJurorForDispute, "Not a juror for this dispute");
        
        // Ensure juror hasn't voted yet
        require(!dispute.votes[msg.sender], "Already voted");
        
        // Record vote
        dispute.votes[msg.sender] = true;
        
        if (supportsClaim) {
            dispute.votesForValidity++;
        } else {
            dispute.votesAgainstValidity++;
        }
        
        emit VoteCast(disputeId, msg.sender, supportsClaim);
        
        // Check if all jurors have voted
        if (dispute.votesForValidity + dispute.votesAgainstValidity == dispute.jurors.length) {
            _resolveDispute(disputeId);
        }
    }
    
    /**
     * @dev Resolve a dispute after voting ends
     */
    function resolveDispute(bytes32 disputeId) external {
        Dispute storage dispute = disputes[disputeId];
        
        require(!dispute.resolved, "Dispute already resolved");
        require(
            block.timestamp >= dispute.timestamp + votingPeriod,
            "Voting period not ended"
        );
        
        _resolveDispute(disputeId);
    }
    
    /**
     * @dev Internal function to handle dispute resolution
     */
    function _resolveDispute(bytes32 disputeId) internal {
        Dispute storage dispute = disputes[disputeId];
        
        bool claimUpheld = dispute.votesForValidity > dispute.votesAgainstValidity;
        
        // Determine which jurors voted with the majority
        address[] memory rewardedJurors = new address[](
            claimUpheld ? dispute.votesForValidity : dispute.votesAgainstValidity
        );
        
        address[] memory penalizedJurors = new address[](
            claimUpheld ? dispute.votesAgainstValidity : dispute.votesForValidity
        );
        
        uint256 rewardedIndex = 0;
        uint256 penalizedIndex = 0;
        
        for (uint256 i = 0; i < dispute.jurors.length; i++) {
            address juror = dispute.jurors[i];
            
            if (dispute.votes[juror] == claimUpheld) {
                rewardedJurors[rewardedIndex] = juror;
                rewardedIndex++;
                
                // Reward juror (in a real implementation, transfer tokens)
                // payable(juror).transfer(rewardAmount);
            } else {
                penalizedJurors[penalizedIndex] = juror;
                penalizedIndex++;
                
                // Penalize juror (in a real implementation, slash stake)
                // stakedAmounts[juror] -= penaltyAmount;
            }
        }
        
        // Mark dispute as resolved
        dispute.resolved = true;
        
        // Notify MemoryManagement contract of resolution
        memoryManagement.resolveDispute(
            dispute.claimId,
            claimUpheld,
            rewardedJurors,
            penalizedJurors
        );
        
        emit DisputeResolved(
            disputeId,
            claimUpheld,
            rewardedJurors,
            penalizedJurors
        );
    }
    
    /**
     * @dev Get dispute details
     */
    function getDispute(bytes32 disputeId)
        external
        view
        returns (
            bytes32 claimId,
            address disputer,
            string memory reason,
            uint256 timestamp,
            bool resolved,
            address[] memory jurors,
            uint256 votesForValidity,
            uint256 votesAgainstValidity
        )
    {
        Dispute storage dispute = disputes[disputeId];
        
        // Create a new array to return jurors (since we can't return storage arrays)
        address[] memory jurorsArray = new address[](dispute.jurors.length);
        for (uint256 i = 0; i < dispute.jurors.length; i++) {
            jurorsArray[i] = dispute.jurors[i];
        }
        
        return (
            dispute.claimId,
            dispute.disputer,
            dispute.reason,
            dispute.timestamp,
            dispute.resolved,
            jurorsArray,
            dispute.votesForValidity,
            dispute.votesAgainstValidity
        );
    }
    
    /**
     * @dev Update jury size
     */
    function setJurySize(uint256 newSize) external {
        require(newSize > 0 && newSize <= 100, "Invalid jury size");
        jurySize = newSize;
    }
    
    /**
     * @dev Update minimum juror stake
     */
    function setMinimumJurorStake(uint256 newStake) external {
        minimumJurorStake = newStake;
    }
    
    /**
     * @dev Update dispute fee
     */
    function setDisputeFee(uint256 newFee) external {
        disputeFee = newFee;
    }
    
    /**
     * @dev Update voting period
     */
    function setVotingPeriod(uint256 newPeriod) external {
        votingPeriod = newPeriod;
    }
    
    // Fallback function to accept ETH
    receive() external payable {}
}
