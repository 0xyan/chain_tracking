from web3 import AsyncWeb3
import asyncio
from datetime import datetime, timedelta
import time
from contract_filter import COMMON_CONTRACTS
import requests
import os
from dotenv import load_dotenv

# Initialize AsyncWeb3
w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider("https://mainnet.base.org"))

load_dotenv()


async def get_contract_age(contract_address):
    url = f"https://api.basescan.org/api"
    params = {
        "module": "account",
        "action": "txlist",
        "address": contract_address,
        "startblock": 0,
        "endblock": 99999999,
        "page": 1,
        "offset": 1,
        "sort": "asc",
        "apikey": os.getenv("BASESCAN_API_KEY"),
    }
    response = requests.get(url, params=params)
    if response.status_code == 200:
        data = response.json()
        if data["result"]:
            first_tx = data["result"][0]
            return datetime.fromtimestamp(int(first_tx["timeStamp"]))


async def get_contract_source(contract_address):
    url = f"https://api.basescan.org/api"
    params = {
        "module": "contract",
        "action": "getsourcecode",
        "address": contract_address,
        "apikey": os.getenv("BASESCAN_API_KEY"),
    }
    response = requests.get(url, params=params)
    if response.status_code == 200:
        data = response.json()
        if data["result"][0]["ContractName"]:
            return data["result"][0]["ContractName"]


async def detect_contract_type(contract_address):
    # ERC165 interface IDs
    INTERFACES = {
        "0x80ac58cd": "ERC721",
        "0xd9b67a26": "ERC1155",
        "0x36372b07": "ERC20",
    }

    types = []
    for interface_id in INTERFACES:
        try:
            supports = await w3.eth.call(
                {
                    "to": contract_address,
                    "data": f"0x01ffc9a7{interface_id[2:]}",  # supportsInterface(bytes4)
                }
            )
            if int.from_bytes(supports, "big"):
                types.append(INTERFACES[interface_id])
        except:
            continue
    return types


async def monitor_contract_activity():
    alerted_contracts = set()
    known_old_contracts = set()
    recent_interactions = {}
    BLOCKS_TO_MONITOR = 5
    INTERACTION_THRESHOLD = 10

    last_processed_block = 0

    while True:
        try:
            block = await w3.eth.get_block("latest", full_transactions=True)
            block_number = block["number"]

            if block_number <= last_processed_block:
                await asyncio.sleep(1)
                continue

            if block_number > last_processed_block + 1:
                print(
                    f"Warning: Skipped {block_number - last_processed_block - 1} blocks"
                )

            print(f"Checking block {block_number}")
            last_processed_block = block_number

            # Track interactions in current block
            current_block_interactions = {}

            for tx in block["transactions"]:
                if tx["to"] and tx["input"] != "0x":
                    contract = tx["to"]
                    if (
                        contract not in COMMON_CONTRACTS
                        and contract not in known_old_contracts
                    ):
                        current_block_interactions[contract] = (
                            current_block_interactions.get(contract, 0) + 1
                        )

            # Update rolling window
            for contract, count in current_block_interactions.items():
                if contract not in recent_interactions:
                    recent_interactions[contract] = []
                recent_interactions[contract].append(count)
                if len(recent_interactions[contract]) > BLOCKS_TO_MONITOR:
                    recent_interactions[contract].pop(0)

            # Prepare contracts to check
            contracts_to_check = []
            for contract, interactions in recent_interactions.items():
                total_interactions = sum(interactions)
                if (
                    total_interactions >= INTERACTION_THRESHOLD
                    and contract not in alerted_contracts
                    and contract not in known_old_contracts
                ):
                    contracts_to_check.append(contract)

            # Check the contracts
            if contracts_to_check:
                age_tasks = [
                    get_contract_age(contract) for contract in contracts_to_check
                ]
                source_tasks = [
                    get_contract_source(contract) for contract in contracts_to_check
                ]
                type_tasks = [
                    detect_contract_type(contract) for contract in contracts_to_check
                ]

                # Run all tasks concurrently
                results = await asyncio.gather(
                    asyncio.gather(*age_tasks),
                    asyncio.gather(*source_tasks),
                    asyncio.gather(*type_tasks),
                )
                contract_infos = results[0]  # Age results
                contract_sources = results[1]  # Source results
                contract_types = results[2]  # Interface detection results

                # Process results
                for contract, contract_info, contract_source, contract_type in zip(
                    contracts_to_check, contract_infos, contract_sources, contract_types
                ):
                    if contract_info:
                        age = datetime.now() - contract_info
                        if age < timedelta(days=7):
                            if age.days > 0:
                                age_str = f"{age.days} days, {age.seconds//3600} hours"
                            elif age.seconds // 3600 > 0:
                                age_str = f"{age.seconds//3600} hours, {(age.seconds%3600)//60} minutes"
                            else:
                                age_str = f"{age.seconds//60} minutes"

                            print(
                                f"\nBlock {block_number} - High activity on new contract: {contract}"
                            )
                            print(
                                f"Contract Name: {contract_source if contract_source else 'Unverified'}"
                            )
                            print(
                                f"Contract Type: {', '.join(contract_type) if contract_type else 'Unknown'}"
                            )
                            print(f"Age: {age_str}")
                            print(
                                f"Total interactions across {len(recent_interactions[contract])} blocks: {sum(recent_interactions[contract])}"
                            )

                            # Skip if it's an ERC20 token
                            if "ERC20" in (contract_type or []):
                                print("Skipping ERC20 token")
                                known_old_contracts.add(contract)
                                if contract in recent_interactions:
                                    del recent_interactions[contract]
                                continue

                            alerted_contracts.add(contract)
                        else:
                            known_old_contracts.add(contract)
                            if contract in recent_interactions:
                                del recent_interactions[contract]

            await asyncio.sleep(1)

        except Exception as e:
            print(f"Error occurred: {str(e)}")
            print(f"Error type: {type(e)}")
            await asyncio.sleep(1)


async def main():
    if await w3.is_connected():
        print("Connected to Base. Starting monitoring...")
        await monitor_contract_activity()
    else:
        print("Failed to connect to Base")


if __name__ == "__main__":
    asyncio.run(main())
