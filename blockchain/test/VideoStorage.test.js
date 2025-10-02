const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("VideoStorage", function () {
  let VideoStorage, BrixaToken;
  let videoStorage, brixaToken;
  let owner, addr1, addr2;
  const TOKEN_SUPPLY = ethers.utils.parseEther("10000000"); // 10 million tokens

  beforeEach(async function () {
    // Get signers
    [owner, addr1, addr2] = await ethers.getSigners();

    // Deploy BrixaToken
    BrixaToken = await ethers.getContractFactory("BrixaToken");
    brixaToken = await BrixaToken.deploy();
    await brixaToken.deployed();

    // Transfer some tokens to test accounts
    await brixaToken.transfer(addr1.address, ethers.utils.parseEther("1000"));
    await brixaToken.transfer(addr2.address, ethers.utils.parseEther("1000"));

    // Deploy VideoStorage with BrixaToken address
    VideoStorage = await ethers.getContractFactory("VideoStorage");
    videoStorage = await VideoStorage.deploy(brixaToken.address);
    await videoStorage.deployed();
  });

  it("Should deploy the contract", async function () {
    expect(await videoStorage.deployed()).to.be.ok;
  });

  it("Should have correct BrixaToken address", async function () {
    expect(await videoStorage.brixaToken()).to.equal(brixaToken.address);
  });

  describe("Video Upload", function () {
    const TEST_CID = "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco";
    const PRICE = ethers.utils.parseEther("1");

    it("Should allow video upload", async function () {
      await videoStorage.connect(addr1).uploadVideo(TEST_CID, PRICE);
      const video = await videoStorage.getVideo(0);
      
      expect(video.cid).to.equal(TEST_CID);
      expect(video.owner).to.equal(addr1.address);
      expect(video.price).to.equal(PRICE);
      expect(video.isListed).to.be.true;
    });

    it("Should prevent duplicate CID uploads", async function () {
      await videoStorage.connect(addr1).uploadVideo(TEST_CID, PRICE);
      await expect(
        videoStorage.connect(addr2).uploadVideo(TEST_CID, PRICE)
      ).to.be.revertedWith("Video with this CID already exists");
    });
  });

  describe("Video Purchase", function () {
    const TEST_CID = "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco";
    const PRICE = ethers.utils.parseEther("1");
    let videoId = 0;

    beforeEach(async function () {
      // Upload a video first
      await videoStorage.connect(addr1).uploadVideo(TEST_CID, PRICE);
      videoId = 0;
    });

    it("Should allow video purchase", async function () {
      // Approve tokens first
      await brixaToken.connect(addr2).approve(videoStorage.address, PRICE);
      
      // Purchase the video
      await expect(videoStorage.connect(addr2).purchaseVideo(videoId))
        .to.emit(videoStorage, 'VideoPurchased')
        .withArgs(videoId, TEST_CID, addr2.address, PRICE);

      // Check video ownership transfer
      const video = await videoStorage.getVideo(videoId);
      expect(video.owner).to.equal(addr2.address);
      expect(video.isListed).to.be.false;

      // Check token transfer
      expect(await brixaToken.balanceOf(addr1.address)).to.equal(
        ethers.utils.parseEther("1000").add(PRICE)
      );
    });

    it("Should prevent purchasing unlisted videos", async function () {
      // Unlist the video
      await videoStorage.connect(addr1).unlistVideo(videoId);
      
      // Try to purchase
      await brixaToken.connect(addr2).approve(videoStorage.address, PRICE);
      await expect(
        videoStorage.connect(addr2).purchaseVideo(videoId)
      ).to.be.revertedWith("Video is not listed for sale");
    });
  });

  describe("Listing Management", function () {
    const TEST_CID = "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco";
    const PRICE = ethers.utils.parseEther("1");
    let videoId = 0;

    beforeEach(async function () {
      // Upload a video first
      await videoStorage.connect(addr1).uploadVideo(TEST_CID, PRICE);
      videoId = 0;
    });

    it("Should allow owner to list and unlist videos", async function () {
      // Unlist
      await videoStorage.connect(addr1).unlistVideo(videoId);
      let video = await videoStorage.getVideo(videoId);
      expect(video.isListed).to.be.false;

      // List again with new price
      const newPrice = ethers.utils.parseEther("2");
      await videoStorage.connect(addr1).listVideo(videoId, newPrice);
      video = await videoStorage.getVideo(videoId);
      expect(video.isListed).to.be.true;
      expect(video.price).to.equal(newPrice);
    });

    it("Should prevent non-owners from listing/unlisting", async function () {
      await expect(
        videoStorage.connect(addr2).unlistVideo(videoId)
      ).to.be.revertedWith("Not the video owner");

      await expect(
        videoStorage.connect(addr2).listVideo(videoId, PRICE)
      ).to.be.revertedWith("Not the video owner");
    });
  });
});
