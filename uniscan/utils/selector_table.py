ERC20_name_selector = 0x06FDDE03
ERC20_symbol_selector = 0x95D89B41
ERC20_decimals_selector = 0x313CE567
ERC20_totalSupply_selector = 0x18160DDD
ERC20_balanceOf_selector = 0x70A08231
ERC20_transfer_selector = 0xA9059CBB
ERC20_transferFrom_selector = 0x23B872DD
ERC20_approve_selector = 0x095EA7B3
ERC20_allowance_selector = 0xDD62ED3E

all_erc20_selector = {
    # "name": ERC20_name_selector,
    # "symbol": ERC20_symbol_selector,
    # "decimals": ERC20_decimals_selector,
    "totalSupply": ERC20_totalSupply_selector,
    "balanceOf": ERC20_balanceOf_selector,
    "transfer": ERC20_transfer_selector,
    "transferFrom": ERC20_transferFrom_selector,
    "approve": ERC20_approve_selector,
    "allowance": ERC20_allowance_selector,
}

ERC721_name_selector = 0x06FDDE03
ERC721_symbol_selector = 0x95D89B41
ERC721_tokenURI_selector = 0xC87B56DD
ERC721_balanceOf_selector = 0x70A08231
ERC721_ownerOf_selector = 0x6352211E
ERC721_safeTransferFrom_with_data_selector = 0xB88D4FDE
ERC721_safeTransferFrom_selector = 0x42842E0E
ERC721_transferFrom_selector = 0x23B872DD
ERC721_approve_selector = 0x095EA7B3
ERC721_setApprovalForAll_selector = 0xA22CB465
ERC721_getApproved_selector = 0x081812FC
ERC721_isApprovedForAll_selector = 0xE985E9C5

all_erc721_selector = {
    # "name": ERC721_name_selector,
    # "symbol": ERC721_symbol_selector,
    # "tokenURI": ERC721_tokenURI_selector,
    "balanceOf": ERC721_balanceOf_selector,
    "ownerOf": ERC721_ownerOf_selector,
    "safeTransferFrom": ERC721_safeTransferFrom_selector,
    "safeTransferFrom_with_data": ERC721_safeTransferFrom_with_data_selector,
    "transferFrom": ERC721_transferFrom_selector,
    "approve": ERC721_approve_selector,
    "setApprovalForAll": ERC721_setApprovalForAll_selector,
    "getApproved": ERC721_getApproved_selector,
    "isApprovedForAll": ERC721_isApprovedForAll_selector,
}

all_standard_selector = {**all_erc20_selector, **all_erc721_selector}

not_consider_protect_standard_selector = {
    "totalSupply": ERC20_totalSupply_selector,
    "balanceOf": ERC20_balanceOf_selector,
    "transfer": ERC20_transfer_selector,
    "transferFrom": ERC20_transferFrom_selector,
    "approve": ERC20_approve_selector,
    "safeTransferFrom": ERC721_safeTransferFrom_selector,
    "safeTransferFrom_with_data": ERC721_safeTransferFrom_with_data_selector,
    "setApprovalForAll": ERC721_setApprovalForAll_selector,
}
