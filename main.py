from web3 import AsyncWeb3
import asyncio
from datetime import datetime, timedelta
import time
from contract_filter import COMMON_CONTRACTS
import requests
import os
from dotenv import load_dotenv
from web3.exceptions import ContractLogicError
import json

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


def send_telegram_message(message):
    token_tg = os.getenv("TELEGRAM_TOKEN")
    id_tg = os.getenv("TELEGRAM_ID")

    url = f"https://api.telegram.org/bot{token_tg}/sendMessage"
    params = {
        "chat_id": id_tg,
        "text": message,
        "parse_mode": "HTML",  # This allows HTML formatting
    }
    try:
        response = requests.post(url, params=params)
        return response.json()
    except Exception as e:
        print(f"Failed to send Telegram message: {e}")


async def get_contract_info(contract_address):
    """Get contract source, name and ABI"""
    url = f"https://api.basescan.org/api"
    params = {
        "module": "contract",
        "action": "getsourcecode",
        "address": contract_address,
        "apikey": os.getenv("BASESCAN_API_KEY"),
    }
    try:
        response = requests.get(url, params=params)
        if response.status_code == 200:
            data = response.json()
            result = data["result"][0]
            contract_name = result["ContractName"]

            # Try to parse ABI
            try:
                abi = json.loads(result["ABI"])
                if abi == "Contract source code not verified":
                    abi = None
            except:
                abi = None

            return {"name": contract_name, "abi": abi}
    except Exception as e:
        print(f"Error getting contract info: {e}")
    return None


async def decode_transaction(tx, abi=None):
    """Decode transaction input data"""
    if not abi:
        # Return raw function signature if no ABI
        return tx["input"][:10]

    try:
        contract = w3.eth.contract(abi=abi)
        func_obj, params = contract.decode_function_input(tx["input"])
        return func_obj.fn_name
    except:
        # Return raw signature if decoding fails
        return tx["input"][:10]


async def get_recent_methods(contract_address):
    """Get last 3 methods called on contract"""
    url = f"https://api.basescan.org/api"
    params = {
        "module": "account",
        "action": "txlist",
        "address": contract_address,
        "page": 1,
        "offset": 3,  # Get last 3 transactions
        "sort": "desc",
        "apikey": os.getenv("BASESCAN_API_KEY"),
    }

    try:
        response = requests.get(url, params=params)
        if response.status_code == 200:
            data = response.json()
            if data["result"]:
                return [tx["input"] for tx in data["result"] if tx["input"] != "0x"]
    except Exception as e:
        print(f"Error getting recent methods: {e}")
    return []


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
                await asyncio.sleep(0.1)
                continue

            print(f"Checking block {block_number}")

            if block_number > last_processed_block + 1:
                print(
                    f"Warning: Skipped {block_number - last_processed_block - 1} blocks"
                )

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
                info_tasks = [
                    get_contract_info(contract) for contract in contracts_to_check
                ]
                methods_tasks = [
                    get_recent_methods(contract) for contract in contracts_to_check
                ]

                # Run all tasks concurrently
                results = await asyncio.gather(
                    asyncio.gather(*age_tasks),
                    asyncio.gather(*info_tasks),
                    asyncio.gather(*methods_tasks),
                )

                contract_ages = results[0]
                contract_infos = results[1]
                recent_methods = results[2]

                # Process results
                for contract, age_info, contract_info, methods in zip(
                    contracts_to_check, contract_ages, contract_infos, recent_methods
                ):
                    if contract_info and contract_info["name"] == "Token":
                        known_old_contracts.add(contract)
                        if contract in recent_interactions:
                            del recent_interactions[contract]
                        continue

                    if age_info:
                        age = datetime.now() - age_info

                        # Skip if contract is too new
                        if age < timedelta(minutes=10):
                            print(
                                f"Skipping contract {contract} - too new ({age.seconds//60} minutes old)"
                            )
                            if contract in recent_interactions:
                                del recent_interactions[contract]
                            continue

                        if age < timedelta(days=7):
                            # Format age string
                            if age.days > 0:
                                age_str = f"{age.days} days, {age.seconds//3600} hours"
                            elif age.seconds // 3600 > 0:
                                age_str = f"{age.seconds//3600} hours, {(age.seconds%3600)//60} minutes"
                            else:
                                age_str = f"{age.seconds//60} minutes"

                            # Decode methods
                            decoded_methods = []
                            if methods:
                                for method in methods[:3]:  # Last 3 methods
                                    if contract_info and contract_info["abi"]:
                                        decoded = await decode_transaction(
                                            {"input": method}, contract_info["abi"]
                                        )
                                    else:
                                        decoded = method[
                                            :10
                                        ]  # Just signature if no ABI
                                    decoded_methods.append(decoded)

                            methods_str = (
                                ", ".join(decoded_methods)
                                if decoded_methods
                                else "No methods found"
                            )

                            message = (
                                f"🚨 <b>New Active Contract Detected</b>\n\n"
                                f"Block: {block_number}\n"
                                f"Address: <a href='https://basescan.org/address/{contract}'>{contract}</a>\n"
                                f"Name: {contract_info['name'] if contract_info else 'Unverified'}\n"
                                f"Age: {age_str}\n"
                                f"Activity: {sum(recent_interactions[contract])} txs in {len(recent_interactions[contract])} blocks\n"
                                f"Recent methods: {methods_str}"
                            )

                            # Send Telegram notification
                            send_telegram_message(message)
                            alerted_contracts.add(contract)

                        else:
                            known_old_contracts.add(contract)
                            if contract in recent_interactions:
                                del recent_interactions[contract]

            await asyncio.sleep(0.1)

        except Exception as e:
            print(f"Error occurred: {str(e)}")
            print(f"Error type: {type(e)}")
            await asyncio.sleep(0.1)


async def main():
    if await w3.is_connected():
        print("Connected to Base. Starting monitoring...")
        await monitor_contract_activity()
    else:
        print("Failed to connect to Base")


if __name__ == "__main__":
    asyncio.run(main())
