from web3 import AsyncWeb3
import asyncio
from datetime import datetime, timedelta
import time
from contract_filter import COMMON_CONTRACTS

# Initialize AsyncWeb3
w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider("https://mainnet.base.org"))


async def get_contract_age(contract_address):
    try:
        # Verify it's actually a contract
        code = await w3.eth.get_code(contract_address)
        if code == b"":  # Not a contract
            return None

        # Binary search approach for finding deployment block
        latest_block = await w3.eth.block_number
        week_ago_block = latest_block - (7 * 24 * 60 * 30)

        left = week_ago_block
        right = latest_block
        deployment_block = None

        # First check if contract exists at earliest block
        code = await w3.eth.get_code(contract_address, block_identifier=left)
        if code != b"":
            return None

        # Binary search for deployment block
        while left <= right:
            mid = (left + right) // 2
            try:
                code = await w3.eth.get_code(contract_address, block_identifier=mid)
                if code == b"":
                    left = mid + 1
                else:
                    deployment_block = mid
                    right = mid - 1
            except Exception:
                left = mid + 1

        if deployment_block:
            block = await w3.eth.get_block(deployment_block)
            return {
                "deployment_block": deployment_block,
                "deployment_time": datetime.fromtimestamp(block["timestamp"]),
            }

    except Exception as e:
        print(f"Error in get_contract_age: {str(e)}")
        return None

    return None


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

            print(f"Checking block {block_number}")
            last_processed_block = block_number

            if block_number > last_processed_block + 1:
                print(
                    f"Warning: Skipped {block_number - last_processed_block - 1} blocks"
                )

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
                if total_interactions >= INTERACTION_THRESHOLD:
                    contracts_to_check.append(contract)

            # Check the contracts
            if contracts_to_check:
                age_tasks = [
                    get_contract_age(contract) for contract in contracts_to_check
                ]
                contract_infos = await asyncio.gather(*age_tasks)

                # Process results
                for contract, contract_info in zip(contracts_to_check, contract_infos):
                    if contract_info:
                        age = datetime.now() - contract_info["deployment_time"]
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
                                f"Deployment time: {contract_info['deployment_time']}"
                            )
                            print(f"Age: {age_str}")
                            print(
                                f"Total interactions across {len(recent_interactions[contract])} blocks: {sum(recent_interactions[contract])}"
                            )

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
