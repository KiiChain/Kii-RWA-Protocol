#!/usr/bin/env python3

import sys
import config
from common import execute_contract, query_contract

#############################
# Import Core Variables #
#############################

OWNER_KEY_NAME = config.OWNER_KEY_NAME
OWNER_KEY_ADDRESS = config.OWNER_KEY_ADDRESS
CONTRACTS = config.CONTRACTS

#############
# Functions #
#############

def add_compliance_to_token(token_address):
    # For now we add the compliances we have to the registry we have
    # Claims compliance
    print(f"Adding claim compliance to token {token_address}...")
    execute_contract(
        CONTRACTS["compliance_registry_address"],
        {
            "add_compliance_module": {
                "token_address": token_address,
                "module_address": CONTRACTS["compliance_claims_address"],
                "module_name": "ClaimsCompliance"
            }
        },
        OWNER_KEY_NAME,
    )
    print("Claim compliance added")

    # Country compliance
    print(f"Adding country compliance to token {token_address}...")
    execute_contract(
        CONTRACTS["compliance_registry_address"],
        {
            "add_compliance_module": {
                "token_address": token_address,
                "module_address": CONTRACTS["compliance_country_restriction_address"],
                "module_name": "ClaimsCompliance"
            }
        },
        OWNER_KEY_NAME,
    )
    print("Country compliance added")

########
# Call #
########
if __name__== "__main__":
  if len(sys.argv) > 1:
      token_address = sys.argv[1]
      print(f"Setting up compliance for token: {token_address}")
      add_compliance_to_token(token_address)
  else:
      token_address = CONTRACTS["cw20_base_address"]
      print(f"Assuming usage of default token address: {token_address}")
      add_compliance_to_token(token_address)
