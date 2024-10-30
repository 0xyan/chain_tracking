from web3 import Web3
from datetime import datetime, timedelta
import time
from contract_filter import COMMON_CONTRACTS

# from eth_utils import function_signature_to_4byte_selector
# from sc_signatures import CONTRACT_SIGNATURES

# Initialize Web3
w3 = Web3(Web3.HTTPProvider("https://mainnet.base.org"))


def get_contract_age(contract_address):
    # Get contract code to verify it's actually a contract
    code = w3.eth.get_code(contract_address)
    if code == b"":  # Not a contract
        return None

    # Binary search approach for finding deployment block
    latest_block = w3.eth.block_number
    week_ago_block = latest_block - (
        7 * 24 * 60 * 30
    )  # ~2s block time, 1 week of blocks

    left = week_ago_block
    right = latest_block
    deployment_block = None

    try:
        # First check if contract exists at earliest block
        code = w3.eth.get_code(contract_address, block_identifier=left)
        if code != b"":
            # Contract was deployed before our time window
            return None

        # Binary search for deployment block
        while left <= right:
            mid = (left + right) // 2

            try:
                code = w3.eth.get_code(contract_address, block_identifier=mid)
                if code == b"":
                    left = mid + 1
                else:
                    deployment_block = mid
                    right = mid - 1
            except Exception:
                # If error occurs, try next block
                left = mid + 1

        if deployment_block:
            # Get the actual deployment transaction
            block = w3.eth.get_block(deployment_block)
            return {
                "deployment_block": deployment_block,
                "deployment_time": datetime.fromtimestamp(block["timestamp"]),
            }

    except Exception as e:
        print(f"Error in get_contract_age: {str(e)}")
        return None

    return None


def monitor_contract_activity():
    alerted_contracts = set()  # Contracts we've already alerted about
    known_old_contracts = set()  # Contracts we know are too old
    contract_age_cache = {}  # Cache for contract deployment info
    recent_interactions = {}
    BLOCKS_TO_MONITOR = 10
    INTERACTION_THRESHOLD = 20

    last_processed_block = 0

    while True:
        try:
            block = w3.eth.get_block("latest", full_transactions=True)
            block_number = block["number"]

            # Only process if it's a new block
            if block_number <= last_processed_block:
                time.sleep(1)
                continue

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
                    ):  # Skip known old contracts
                        current_block_interactions[contract] = (
                            current_block_interactions.get(contract, 0) + 1
                        )

            # Update sliding window
            for contract, count in current_block_interactions.items():
                if contract not in recent_interactions:
                    recent_interactions[contract] = []
                recent_interactions[contract].append(count)
                if len(recent_interactions[contract]) > BLOCKS_TO_MONITOR:
                    recent_interactions[contract].pop(0)

            # Check for high activity contracts
            for contract, interactions in recent_interactions.items():
                total_interactions = sum(interactions)
                if (
                    total_interactions >= INTERACTION_THRESHOLD
                    and contract not in alerted_contracts
                    and contract not in known_old_contracts
                ):  # Extra check

                    # Check contract age
                    if contract not in contract_age_cache:
                        contract_age_cache[contract] = get_contract_age(contract)

                    contract_info = contract_age_cache[contract]
                    if contract_info:
                        age = datetime.now() - contract_info["deployment_time"]
                        if age < timedelta(days=7):
                            print(
                                f"\nBlock {block_number} - High activity on new contract: {contract}"
                            )
                            print(f"Contract ge: {age}")
                            print(
                                f"Total interactions across {len(interactions)} blocks: {total_interactions}"
                            )
                            alerted_contracts.add(contract)
                        else:
                            # Contract is too old, remember this
                            known_old_contracts.add(contract)
                            # Clean up its data
                            if contract in recent_interactions:
                                del recent_interactions[contract]
                            if contract in contract_age_cache:
                                del contract_age_cache[contract]

            # Periodic cleanup (every 100 blocks)
            if block_number % 100 == 0:
                current_time = datetime.now()
                # Clean up age cache and move old contracts to known_old_contracts
                for addr, info in contract_age_cache.items():
                    if current_time - info["deployment_time"] >= timedelta(days=7):
                        known_old_contracts.add(addr)
                        if addr in recent_interactions:
                            del recent_interactions[addr]

                # Clean up the cache
                contract_age_cache = {
                    addr: info
                    for addr, info in contract_age_cache.items()
                    if addr not in known_old_contracts
                }

            time.sleep(1)

        except Exception as e:
            print(f"Error occurred: {str(e)}")
            print(f"Error type: {type(e)}")
            time.sleep(1)


if __name__ == "__main__":
    if w3.isConnected():
        print("Connected to Base. Starting monitoring...")
        monitor_contract_activity()
    else:
        print("Failed to connect to Base")
