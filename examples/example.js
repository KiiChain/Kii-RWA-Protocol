require('dotenv').config();
const { mint, transfer } = require('../src/index.js');

const destination = process.env.DESTINATION;
const ethers = require('ethers');
const amount = ethers.utils.parseUnits('1', 18);

async function main() {
  await mint(destination, amount);
  await transfer(destination, amount);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});

