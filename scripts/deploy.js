const hre = require("hardhat");

async function main() {
  const RWA = await hre.ethers.getContractFactory("RWA");
  const rwa = await RWA.deploy();
  await rwa.deployed();
  console.log("✅ RWA deployed to:", rwa.address);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

