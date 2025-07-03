#!/usr/bin/env python3

import config
import sys
from common import create_pair, instantiate_contract, store_contract
from compliance_setup import add_compliance_claim_to_token, add_compliance_to_token

#############################
# Import Core Variables #
#############################

OWNER_KEY_NAME = config.OWNER_KEY_NAME
OWNER_KEY_ADDRESS = config.OWNER_KEY_ADDRESS
TRUSTED_ISSUER_KEY_NAME = config.TRUSTED_ISSUER_KEY_NAME
TRUSTED_ISSUER_KEY_ADDRESS = config.TRUSTED_ISSUER_KEY_ADDRESS
CONTRACTS = config.CONTRACTS
CW20_BASE_CODE_ID = config.CW20_BASE_CODE_ID
FACTORY_ADDRESS = config.FACTORY_ADDRESS

#############
# Functions #
#############

# Example json setup
# cw20_base_init_msg = {
#     "token_info": {
#         "name": "Test Token",
#         "symbol": "TEST",
#         "decimals": 6,
#         "initial_balances": [{"address": OWNER_KEY_ADDRESS, "amount": "1000000"}],
#     },
#     "registries": {
#         "compliance_address": CONTRACTS["compliance_registry_address"],
#     },
# }

# Deploy trex creates a new instance of a trex contract with the default owner
def deploy_trex(json_setup):
    print("Deploying trex ")
    trex_base_address = instantiate_contract(
        CW20_BASE_CODE_ID, json_setup, "T-REX", OWNER_KEY_NAME
    )
    print(f"Contract deployed with address: {trex_base_address}")
    return trex_base_address

# create liquidity creates a token pair associated with the TREX and gives it liquidity
def create_liquidity(token_address):
    print("Creating pair to kii ")
    pair_msg = {
      "create_pair": {
        "pair_type": {
          "xyk": {}
        },
        "asset_infos": [
          {
            "native_token": {
              "denom": "akii"
            }
          },
          {
            "token": {
              "contract_addr": token_address
            }
          }
        ],
        "init_params": "e30="
      }
    }
    pair_address = create_pair(FACTORY_ADDRESS, pair_msg, OWNER_KEY_NAME)
    print(f"Giving an identity to pair {pair_address}")
    print("Adding liquidity to it")

# setup trex deploys and sets up a pool and compliance for a trex
def setup_trex(json_setup):
    print("Setting up new trex token")
    # Deploy new instance of contract with our default owner
    trex_address = deploy_trex(json_setup)

    # Add compliance modules to token, using same ones we already have
    # This means the same trusted issuer will be used
    add_compliance_to_token(trex_address)

    # Adding claim to token, assuming default topic 1
    add_compliance_claim_to_token(trex_address)

# Flow to add a new asset
# - Create a new CW_20
# - Add compliances modules to token
# - Add claim topic to token
# - Create a new pair between CW_20 and native token
#   - This will be a pool
#   - In the future we might want different pairs
# - Set up CW_20 compliance
#   - We need to register a claim limitation for the token
#     - We specify a topic (we using 1 for now)
#     - Needs a trusted issuer
