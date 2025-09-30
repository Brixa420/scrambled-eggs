const { ethers } = require("hardhat");

module.exports = async ({ getNamedAccounts, deployments, network }) => {
  const { deploy, log, get } = deployments;
  const { deployer } = await getNamedAccounts();

  // Get the deployed BrixaToken address
  const brixaToken = await get("BrixaToken");
  
  log("Deploying VideoStorage...");
  const videoStorage = await deploy("VideoStorage", {
    from: deployer,
    args: [brixaToken.address],
    log: true,
    waitConfirmations: 6,
  });

  log(`VideoStorage deployed at: ${videoStorage.address}`);
  return videoStorage.address;
};

module.exports.tags = ["all", "videostorage"];
