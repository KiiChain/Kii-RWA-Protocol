#!/usr/bin/env python3

import config
import sys
from common import create_pair, increase_allowance, instantiate_contract, provide_liquidity
from compliance_setup import add_compliance_claim_to_token, add_compliance_to_token, whitelist_address

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

# Deploy trex creates a new instance of a trex contract with the default owner
def deploy_trex():
    print("Deploying trex")
    cw20_init_msg = {
      "token_info": {
          "name": "Test Token",
          "symbol": "TEST",
          "decimals": 6,
          "initial_balances": [{"address": OWNER_KEY_ADDRESS, "amount": "1000000"}],
      },
      "registries": {
          "compliance_address": CONTRACTS["compliance_registry_address"],
      },
  }
    trex_base_address = instantiate_contract(
        CW20_BASE_CODE_ID, cw20_init_msg, "T-REX", OWNER_KEY_NAME
    )
    print(f"Contract deployed with address: {trex_base_address}")
    return trex_base_address

# create liquidity creates a token pair associated with the TREX and gives it liquidity
def create_liquidity(token_address, cw20_amount, native_amount):
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
    print(f"Pair created with address {pair_address}")

    print("Giving allowance to liquidity")
    increase_allowance(token_address, pair_address, OWNER_KEY_NAME, cw20_amount)

    print("Providing liquidity to pair")
    provide_liquidity(pair_address, token_address, cw20_amount, native_amount, OWNER_KEY_NAME)
    return pair_address

# setup trex deploys and sets up a pool and compliance for a trex
def setup_trex():
    print("Setting up new trex token")
    # Deploy new instance of contract with our default owner
    trex_address = deploy_trex()

    # Create pair and liquidity
    # Please save this pair somewhere, it is important to do swaps in the future
    cw20_amount = 1000000
    native_amount = 10000000000000
    pair_address = create_liquidity(trex_address, cw20_amount, native_amount)

    # Add compliance modules to token, using same ones we already have
    # This means the same trusted issuer will be used
    add_compliance_to_token(trex_address)

    # Whitelist the pair address so it can pass claims
    whitelist_address(pair_address)

    # Adding claim to token, assuming default topic 1
    add_compliance_claim_to_token(trex_address)

########
# Call #
########

if __name__== "__main__":
  setup_trex()
