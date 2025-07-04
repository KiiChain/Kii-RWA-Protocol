#!/usr/bin/env python3

import subprocess
import json
import requests

#############################
# Core Deployment Variables #
#############################

KIICHAIN = "kiichaind"
RPC_URL = "https://rpc.uno.sentry.testnet.v3.kiivalidator.com"
LCD_NODE = "https://lcd.uno.sentry.testnet.v3.kiivalidator.com"
CHAIN_ID = "oro_1336-1"
TXFLAG = [
    "--gas",
    "auto",
    "--gas-adjustment",
    "1.2",
    "--gas-prices",
    "500000000000akii",
    "--keyring-backend",
    "test",
    "--node",
    RPC_URL,
    "--chain-id",
    CHAIN_ID,
    "-y",
    "-o",
    "json",
]

##################
# Util functions #
##################

# Define all the helper functions
def run_cmd(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout, result.stderr

# Get the key address from the key name
def get_key_address(key_name):
    # Build the command to get the key address
    cmd = [KIICHAIN, "keys", "show", key_name, "--output", "json"]

    # Run the command
    result, err = run_cmd(cmd)

    # If there is an error, we raise
    if err:
        raise Exception(f"Failed to get key address: {err}")

    # Parse the result and return the address
    key_info = json.loads(result)
    return key_info["address"]

# Check check a tx until a result is returned
def check_tx_until_result(tx_hash):
    while True:
      # We can check the TX using the APIs
      res = requests.get(f"{LCD_NODE}/cosmos/tx/v1beta1/txs/{tx_hash}")

      # If the response is 404, this means the TX is not yet processed
      if res.status_code == 404:
          continue

      # If the response is different than 200, we raise
      if res.status_code != 200:
          raise Exception(f"Failed to check tx {tx_hash}: {res.text}")

      # Reaching this point means the TX is processed
      result = res.json()
      code = result["tx_response"]["code"]

      # If the code isn't 0 we raise
      if code != 0:
          raise Exception(f"Transaction {tx_hash} failed with code {code}: {result}")

      # Reaching this point we can return the result
      return result

# Store contract stores a contract and return the TX hash
def store_contract(path, from_key):
    # Build the cmd for deploying the contract
    cmd = [KIICHAIN, "tx", "wasm", "store", path, "--from", from_key] + TXFLAG

    # Run the command to store the contract
    result, err = run_cmd(cmd)
    if len(err.splitlines()) > 1 or "gas estimate" not in err.splitlines()[0]:
        raise Exception(f"Failed to store contract: {err}")

    # Get the result and the code
    code = json.loads(result)["code"]
    tx_hash = json.loads(result)["txhash"]

    # Check if the code was success
    if code != 0:
        raise Exception(f"Failed to store contract: {result}")

    # If all is fine we wait for the tx to be processed
    result = check_tx_until_result(tx_hash)

    # From the result we can get the code id
    code_id = next(
        attr["value"]
        for event in result["tx_response"]["events"]
        for attr in event["attributes"]
        if attr["key"] == "code_id"
    )

    # Return the code id
    return code_id

# Instantiate contract instantiates a contract with the given code ID and init message
def instantiate_contract(code_id, init_msg, label, from_key):
    # Get the key address from the key name
    key_address = get_key_address(from_key)

    # Build the cmd for instantiating the contract
    cmd = [
        KIICHAIN,
        "tx",
        "wasm",
        "instantiate",
        code_id,
        json.dumps(init_msg),
        "--label",
        label,
        "--admin",
        key_address,
        "--from",
        from_key,
    ] + TXFLAG

    # Run the command to instantiate the contract
    result, err = run_cmd(cmd)
    if len(err.splitlines()) > 1 or "gas estimate" not in err.splitlines()[0]:
        raise Exception(f"Failed to instantiate contract: {err}")

    # Get the result and the code
    code = json.loads(result)["code"]
    tx_hash = json.loads(result)["txhash"]

    # Check if the code was success
    if code != 0:
        raise Exception(f"Failed to instantiate contract: {result}")

    # If all is fine we wait for the tx to be processed
    result = check_tx_until_result(tx_hash)

    # Get the contract address from the result
    contract_address = next(
        attr["value"]
        for event in result["tx_response"]["events"]
        for attr in event["attributes"]
        if attr["key"] == "_contract_address"
    )

    # Return the contract address
    return contract_address

# Execute contract executes a contract with the given message
def execute_contract(contract_address, msg, from_key):
    # Build the command to execute the contract
    cmd = [
        KIICHAIN,
        "tx",
        "wasm",
        "execute",
        contract_address,
        json.dumps(msg),
        "--from",
        from_key,
    ] + TXFLAG

    # Run the command
    result, err = run_cmd(cmd)
    if len(err.splitlines()) > 1 or "gas estimate" not in err.splitlines()[0]:
        raise Exception(f"Failed to execute contract: {err}")

    # Get the result and the code
    code = json.loads(result)["code"]
    tx_hash = json.loads(result)["txhash"]

    # Check if the code was success
    if code != 0:
        raise Exception(f"Failed to execute contract: {result}")

    # If all is fine we wait for the tx to be processed
    return check_tx_until_result(tx_hash)

# Create pair executes a kiichaind command to create a factory token as a pair
def create_pair(factory_address, msg, from_key):
    # Build the command to execute the contract
    cmd = [
        KIICHAIN,
        "tx",
        "wasm",
        "execute",
        factory_address,
        json.dumps(msg),
        "--from",
        from_key,
    ] + TXFLAG

    # Run the command
    result, err = run_cmd(cmd)
    if len(err.splitlines()) > 1 or "gas estimate" not in err.splitlines()[0]:
        raise Exception(f"Failed to execute contract: {err}")

    # Get the result and the code
    code = json.loads(result)["code"]
    tx_hash = json.loads(result)["txhash"]

    # Check if the code was success
    if code != 0:
        raise Exception(f"Failed to execute contract: {result}")

    # If all is fine we wait for the tx to be processed
    result = check_tx_until_result(tx_hash)

    # Get the pair address from the result
    pair_address = next(
        attr["value"]
        for event in result["tx_response"]["events"]
        for attr in event["attributes"]
        if event["type"] == "wasm" and attr["key"] == "pair_contract_addr"
    )

    # Return the contract address
    return pair_address

def increase_allowance(cw_token_address, pair_address, key_name, amount):
    """Increase allowance for the pair contract to spend CW20 tokens"""
    allowance_msg = {
        "increase_allowance": {
            "spender": pair_address,
            "amount": str(amount)
        }
    }

    cmd = [
        KIICHAIN,
        "tx",
        "wasm",
        "execute",
        cw_token_address,
        json.dumps(allowance_msg),
        "--from",
        key_name,
    ] + TXFLAG

    result, err = run_cmd(cmd)
    if len(err.splitlines()) > 1 or "gas estimate" not in err.splitlines()[0]:
        raise Exception(f"Failed to increase allowance: {err}")

    # Check transaction result
    result_json = json.loads(result)
    if result_json.get("code") != 0:
        raise Exception(f"Failed to increase allowance: {result}")

    tx_hash = result_json["txhash"]
    events = check_tx_until_result(tx_hash)
    print("Allowance increased successfully")
    return events

def provide_liquidity(pair_address, cw_token_address, cw20_amount, native_amount, key_name):
    """Provide liquidity to the pair"""
    liquidity_msg = {
        "provide_liquidity": {
            "assets": [
                {
                    "info": {
                        "token": {"contract_addr": cw_token_address}
                    },
                    "amount": str(cw20_amount)
                },
                {
                    "info": {
                        "native_token": {"denom": "akii"}
                    },
                    "amount": str(native_amount)
                }
            ],
            "slippage_tolerance": "0.02",
            "auto_stake": False
        }
    }

    cmd = [
        KIICHAIN,
        "tx",
        "wasm",
        "execute",
        pair_address,
        json.dumps(liquidity_msg),
        "--amount",
        f"{native_amount}akii",
        "--from",
        key_name,
    ] + TXFLAG

    result, err = run_cmd(cmd)
    if len(err.splitlines()) > 1 or "gas estimate" not in err.splitlines()[0]:
        raise Exception(f"Failed to provide liquidity: {err}")

    # Check transaction result
    result_json = json.loads(result)
    if result_json.get("code") != 0:
        raise Exception(f"Failed to provide liquidity: {result}")

    tx_hash = result_json["txhash"]
    events = check_tx_until_result(tx_hash)
    print("Liquidity added successfully")
    return events

# Query contract queries a contract with the given query message
def query_contract(contract_address, query_msg):
    # Build the command to query the contract
    cmd = [
        KIICHAIN,
        "query",
        "wasm",
        "contract-state",
        "smart",
        contract_address,
        json.dumps(query_msg),
        "--node", RPC_URL,
        "-o", "json"
    ]

    # Run the command
    result, err = run_cmd(cmd)
    if err:
        raise Exception(f"Failed to query contract: {err}")

    # Parse and return the result
    return json.loads(result)

def query_contract_fail_with(contract_address, query_msg, expected_err):
    # Build the command to query the contract
    cmd = [
        KIICHAIN,
        "query",
        "wasm",
        "contract-state",
        "smart",
        contract_address,
        json.dumps(query_msg),
        "--node", RPC_URL,
        "-o", "json"
    ]

    # Run the command
    result, err = run_cmd(cmd)
    if err:
        if expected_err not in err:
          raise Exception(f"Contract failed with unexpected error: {err}")
        return result, True

    # Parse and return the result
    return result, False
