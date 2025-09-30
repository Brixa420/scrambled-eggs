const { ethers } = require("hardhat");

module.exports = async ({ getNamedAccounts, deployments }) => {
  const { deploy, log } = deployments;
  const { deployer } = await getNamedAccounts();

  log("Deploying BrixaToken...");
  const brixaToken = await deploy("BrixaToken", {
    from: deployer,
    args: [],
    log: true,
    waitConfirmations: 6,
  });

  log(`BrixaToken deployed at: ${brixaToken.address}`);
  return brixaToken.address;
};

module.exports.tags = ["all", "brixtoken"];
