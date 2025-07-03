require('dotenv').config();
const { ethers } = require('ethers');
const abi = require('./abi.json');

const provider = new ethers.providers.JsonRpcProvider(process.env.RPC_URL);
const wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);

const contractAddress = process.env.CONTRACT_ADDRESS;
const contract = new ethers.Contract(contractAddress, abi, wallet);

async function mint(to, amount) {
  const tx = await contract.mint(to, amount);
  console.log("Mint TX:", tx.hash);
  await tx.wait();
  console.log("✅ Mint successful");
}

async function transfer(to, amount) {
  const tx = await contract.transferAsset(to, amount);
  console.log("Transfer TX:", tx.hash);
  await tx.wait();
  console.log("✅ Transfer successful");
}

module.exports = { mint, transfer };

