CONTRACT_SIGNATURES = {
    "ERC20": {
        "signatures": [
            "totalSupply()",
            "balanceOf(address)",
            "transfer(address,uint256)",
            "transferFrom(address,address,uint256)",
            "approve(address,uint256)",
            "allowance(address,address)",
        ],
        "required_matches": 4,  # Need at least 4 matches to be considered ERC20
    },
    "UniswapV2Pool": {
        "signatures": [
            "mint(address)",
            "burn(address)",
            "swap(uint256,uint256,address,bytes)",
            "skim(address)",
            "sync()",
            "getReserves()",
        ],
        "required_matches": 4,
    },
    "UniswapV3Pool": {
        "signatures": [
            "mint(address,int24,int24,uint128,bytes)",
            "collect(address,int24,int24,uint128,uint128)",
            "burn(int24,int24,uint128)",
            "swap(address,bool,int256,uint160,bytes)",
            "flash(address,uint256,uint256,bytes)",
        ],
        "required_matches": 3,
    },
}
