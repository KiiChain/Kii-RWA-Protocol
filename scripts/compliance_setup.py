#!/usr/bin/env python3

import sys
import config
from common import execute_contract

#############################
# Import Core Variables #
#############################

OWNER_KEY_NAME = config.OWNER_KEY_NAME
OWNER_KEY_ADDRESS = config.OWNER_KEY_ADDRESS
CONTRACTS = config.CONTRACTS

#############
# Functions #
#############

def remove_old_compliances(token_address):
    # For now we add the compliances we have to the registry we have
    # Claims compliance
    print(f"Removing old claim compliance from token {token_address}...")
    execute_contract(
        CONTRACTS["compliance_registry_address"],
        {
            "remove_compliance_module": {
                "token_address": token_address,
                "module_address": CONTRACTS["compliance_claims_address"],
            }
        },
        OWNER_KEY_NAME,
    )
    print("Claim compliance removed")

    # Country compliance
    print(f"Removing old country compliance from token {token_address}...")
    execute_contract(
        CONTRACTS["compliance_registry_address"],
        {
            "remove_compliance_module": {
                "token_address": token_address,
                "module_address": CONTRACTS["compliance_country_restriction_address"],
            }
        },
        OWNER_KEY_NAME,
    )
    print("Country compliance removed")

def add_compliance_to_token(token_address):
    # For now we add the compliances we have to the registry we have
    # Claims compliance
    print(f"Adding claim compliance to token {token_address}...")
    execute_contract(
        CONTRACTS["compliance_registry_address"],
        {
            "add_compliance_module": {
                "token_address": token_address,
                "module_address": CONTRACTS["compliance_claims_wrapper_address"],
                "module_name": "ClaimsComplianceWrapped"
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
                "module_address": CONTRACTS["compliance_country_wrapper_address"],
                "module_name": "CountryComplianceWrapped"
            }
        },
        OWNER_KEY_NAME,
    )
    print("Country compliance added")

def add_compliance_claim_to_token(token_address):
    print(f"Adding claim topic restriction to token {token_address}...")
    execute_contract(
        CONTRACTS["claim_topics_address"],
        {
            "add_claim_topic_for_token": {
                "token_addr": token_address,
                "topic": "1",
            }
        },
        OWNER_KEY_NAME,
    )
    print("Restriction added")

def whitelist_address(address):
    print(f"Whitelisting address {address} on country compliance wrapper")
    execute_contract(
        CONTRACTS["compliance_country_wrapper_address"],
        {
            "add_address_to_whitelist": {
                "address": address,
            }
        },
        OWNER_KEY_NAME,
    )
    print(f"Whitelisting address {address} on claims compliance wrapper")
    execute_contract(
        CONTRACTS["compliance_claims_wrapper_address"],
        {
            "add_address_to_whitelist": {
                "address": address,
            }
        },
        OWNER_KEY_NAME,
    )


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
