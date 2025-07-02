#!/usr/bin/env python3

import config
import sys
from common import execute_contract, get_key_address, query_contract

#############################
# Import Core Variables #
#############################

CONTRACTS = config.CONTRACTS

#############
# Functions #
#############

def balance_of(token_address, user_key):
    print(f"Checking balance of {user_key} on CW20 {token_address}")
    balance = query_contract(
        token_address,
        {"balance": {"address": get_key_address(user_key)}},
    )
    print(f"Balance: {balance}")

########
# Call #
########

if len(sys.argv) > 2:
    user_key = sys.argv[1]
    token_address = sys.argv[2]
    balance_of(token_address, user_key)
elif len(sys.argv) > 1:
    user_key = sys.argv[1]
    print("Assuming usage of default contract")
    balance_of(CONTRACTS["cw20_base_address"], user_key)
else:
    print("Usage: ./balance user_key [token_address]")
