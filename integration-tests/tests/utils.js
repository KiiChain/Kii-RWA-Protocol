const { DirectSecp256k1HdWallet } = require("@cosmjs/proto-signing");
const { GasPrice } = require("@cosmjs/stargate");
const { SigningCosmWasmClient } = require("@cosmjs/cosmwasm-stargate");
const { exec } = require('child_process');
const fs = require('fs');

async function setupWallet() {
  const rpcEndpoint = "http://127.0.0.1:26657/";
  // Create new wallet with Sei address prefix
  const wallet = await DirectSecp256k1HdWallet.generate(24, { prefix: "sei" });
  const [account] = await wallet.getAccounts();
  const gasPrice = GasPrice.fromString("0.1usei");
  console.log("New Sei account: ", account.address, "\n");
  const client = await SigningCosmWasmClient.connectWithSigner(rpcEndpoint, wallet, { gasPrice });

  // Funding new wallet with 100,000 SEI
  exec(`~/go/bin/seid tx bank send admin ${account.address} 100000000000usei --fees 10000usei -y`, (err, stdout, stderr) => {
    if (err) {
      //some err occurred
      console.error(err)
    }
  });
  await new Promise(resolve => setTimeout(resolve, 500));
  // Query new wallet balance
  return {
    account,
    client,
  };
}

async function deployContract(client, senderAddress, contractName, initMsg) {
  // Read the wasm file
  console.log("Deploying contract: ", contractName);
  const wasmFilePath = `../target/wasm32-unknown-unknown/release/${contractName}.wasm`;
  const wasmCode = fs.readFileSync(wasmFilePath);
  
  // Upload the contract code
  const uploadResult = await client.upload(senderAddress, wasmCode, "auto");
  console.log(`${contractName} contract uploaded. Code ID:`, uploadResult.codeId);

  const instantiateResult = await client.instantiate(
    senderAddress,
    uploadResult.codeId,
    initMsg,
    contractName,
    "auto"
  );
  console.log(`${contractName} contract instantiated.\nAddress:`, instantiateResult.contractAddress, "\n\n");

  return {
    contractCodeId: uploadResult.codeId,
    contractAddress: instantiateResult.contractAddress,
  };
}

async function executeContract(client, senderAddress, contractAddress, msg) {
  try {
    const result = await client.execute(
      senderAddress,
      contractAddress,
      msg,
      {
        amount: [{ denom: "usei", amount: "50000" }],
        gas: "1000000",
      },
    );
    return result;
  } catch (error) {
    throw error;
  }
}

async function queryContract(client, contractAddress, msg) {
  try {
    const result = await client.queryContractSmart(contractAddress, msg);
    return result;
  } catch (error) {
    console.error("Error querying contract:", error);
    throw error;
  }
}

module.exports = {
    setupWallet,
    deployContract,
    executeContract,
    queryContract
};
