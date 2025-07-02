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

def transfer(sender, receiver, quantity):
    print(f"{sender} is transferring {quantity} to {receiver}. Both need to have claims and compliance")
    execute_contract(
        CONTRACTS["cw20_base_address"],
        {
            "transfer": {
                "recipient" : get_key_address(receiver),
                "amount": quantity
            }
        },
        sender,
    )
    print("Send completed")

########
# Call #
########
if __name__== "__main__":
  if len(sys.argv) > 3:
      sender = sys.argv[1]
      receiver = sys.argv[2]
      quantity = sys.argv[3]
      transfer(sender, receiver, quantity)
  else:
      print("Usage: ./transfer sender_key_name receiver_key_name quantity")
