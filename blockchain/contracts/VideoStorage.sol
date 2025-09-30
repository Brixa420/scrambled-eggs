// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract VideoStorage is Ownable {
    struct Video {
        string cid; // IPFS content identifier
        address owner;
        uint256 uploadTime;
        uint256 price; // Price in BRIXA tokens
        bool isListed;
    }

    IERC20 public brixaToken;
    uint256 public videoCount;
    mapping(uint256 => Video) public videos;
    mapping(string => bool) private cidExists;

    event VideoUploaded(
        uint256 indexed videoId,
        string cid,
        address indexed owner,
        uint256 price
    );
    event VideoPurchased(
        uint256 indexed videoId,
        string cid,
        address indexed buyer,
        uint256 price
    );

    constructor(address _brixaToken) Ownable(msg.sender) {
        require(_brixaToken != address(0), "Invalid token address");
        brixaToken = IERC20(_brixaToken);
    }

    function uploadVideo(string memory _cid, uint256 _price) external {
        require(bytes(_cid).length > 0, "CID cannot be empty");
        require(!cidExists[_cid], "Video with this CID already exists");
        
        uint256 videoId = videoCount++;
        videos[videoId] = Video({
            cid: _cid,
            owner: msg.sender,
            uploadTime: block.timestamp,
            price: _price,
            isListed: _price > 0
        });
        
        cidExists[_cid] = true;
        
        emit VideoUploaded(videoId, _cid, msg.sender, _price);
    }

    function purchaseVideo(uint256 _videoId) external {
        Video storage video = videos[_videoId];
        require(video.owner != address(0), "Video does not exist");
        require(video.isListed, "Video is not listed for sale");
        require(msg.sender != video.owner, "Cannot purchase your own video");
        
        // Transfer tokens from buyer to video owner
        bool success = brixaToken.transferFrom(
            msg.sender,
            video.owner,
            video.price
        );
        require(success, "Token transfer failed");
        
        // Transfer ownership to buyer
        video.owner = msg.sender;
        video.isListed = false;
        
        emit VideoPurchased(_videoId, video.cid, msg.sender, video.price);
    }

    function listVideo(uint256 _videoId, uint256 _price) external {
        Video storage video = videos[_videoId];
        require(video.owner == msg.sender, "Not the video owner");
        require(!video.isListed, "Video already listed");
        
        video.price = _price;
        video.isListed = true;
    }

    function unlistVideo(uint256 _videoId) external {
        Video storage video = videos[_videoId];
        require(video.owner == msg.sender, "Not the video owner");
        require(video.isListed, "Video not listed");
        
        video.isListed = false;
    }

    function getVideo(uint256 _videoId) external view returns (
        string memory cid,
        address owner,
        uint256 uploadTime,
        uint256 price,
        bool isListed
    ) {
        Video storage video = videos[_videoId];
        require(video.owner != address(0), "Video does not exist");
        
        return (
            video.cid,
            video.owner,
            video.uploadTime,
            video.price,
            video.isListed
        );
    }
}
