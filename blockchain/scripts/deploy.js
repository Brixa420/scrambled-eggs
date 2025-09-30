const { ethers } = require("hardhat");
const { verify } = require("./verify");

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying contracts with the account:", deployer.address);
  console.log("Account balance:", (await deployer.getBalance()).toString());

  // Deploy BrixaToken
  console.log("Deploying BrixaToken...");
  const BrixaToken = await ethers.getContractFactory("BrixaToken");
  const brixaToken = await BrixaToken.deploy();
  await brixaToken.deployed();
  console.log("BrixaToken deployed to:", brixaToken.address);

  // Deploy VideoStorage with BrixaToken address
  console.log("Deploying VideoStorage...");
  const VideoStorage = await ethers.getContractFactory("VideoStorage");
  const videoStorage = await VideoStorage.deploy(brixaToken.address);
  await videoStorage.deployed();
  console.log("VideoStorage deployed to:", videoStorage.address);

  // Deploy PinningIncentives
  console.log("Deploying PinningIncentives...");
  const PinningIncentives = await ethers.getContractFactory("PinningIncentives");
  const pinningIncentives = await PinningIncentives.deploy(brixaToken.address);
  await pinningIncentives.deployed();
  console.log("PinningIncentives deployed to:", pinningIncentives.address);

  // Deploy StorageProof
  console.log("Deploying StorageProof...");
  const StorageProof = await ethers.getContractFactory("StorageProof");
  const storageProof = await StorageProof.deploy();
  await storageProof.deployed();
  console.log("StorageProof deployed to:", storageProof.address);

  // Deploy StreamingNode
  console.log("Deploying StreamingNode...");
  const StreamingNode = await ethers.getContractFactory("StreamingNode");
  const streamingNode = await StreamingNode.deploy(brixaToken.address);
  await streamingNode.deployed();
  console.log("StreamingNode deployed to:", streamingNode.address);

  // Verify contracts on Polygonscan if not on local network
  if (process.env.POLYGONSCAN_API_KEY) {
    console.log("Waiting for block confirmations...");
    await brixaToken.deployTransaction.wait(6);
    
    console.log("Verifying contracts...");
    await verify(brixaToken.address, []);
    await verify(videoStorage.address, [brixaToken.address]);
    await verify(pinningIncentives.address, [brixaToken.address]);
    await verify(storageProof.address, []);
    await verify(streamingNode.address, [brixaToken.address]);
  }

  console.log("\nDeployment Summary:");
  console.log("------------------");
  console.log(`BrixaToken: ${brixaToken.address}`);
  console.log(`VideoStorage: ${videoStorage.address}`);
  console.log(`PinningIncentives: ${pinningIncentives.address}`);
  console.log(`StorageProof: ${storageProof.address}`);
  console.log(`StreamingNode: ${streamingNode.address}`);
  console.log("\nTo interact with contracts, use the above addresses.");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
