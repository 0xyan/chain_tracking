from web3 import Web3
from datetime import datetime, timedelta
import time
from contract_filter import COMMON_CONTRACTS

# Initialize Web3
w3 = Web3(Web3.HTTPProvider("https://mainnet.base.org"))


"""
block = w3.eth.get_block("latest", full_transactions=True)

block_number = block["number"]

for tx in block["transactions"]:
    if tx["to"] and tx["input"] != "0x":
        contract = tx["to"]
        if contract not in COMMON_CONTRACTS:
            print(contract)
"""

code = w3.eth.get_code("0x937ac71Cf368875d6708042986DFbE28dE3d2eAE")

print(code)
