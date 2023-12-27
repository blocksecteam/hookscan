from typing import List, MutableSet, Optional, Tuple

from uniscan.components.evm_instructions import Address, Call, Callcode, Delegatecall, Staticcall
from uniscan.core.instruction_instance import ValueInstance
from uniscan.core.traversal_info import TraversalInfo
from uniscan.detectors.base_detector import BaseDetector
from uniscan.utils.ordered_set import OrderedSet as set


class UniswapGetCallback(BaseDetector):
    """Find callback functions that are passed by lock to pool manager.

    This detector enumerates all the functions (tagged by selector) that are passed by `lock` to pool manager.
    """

    def __init__(self) -> None:
        super().__init__()
        self.callback_functions: MutableSet[Tuple[int, Optional[str]]] = set()  # Set[(selector, name)]
        self.callback_keys = (Call, Delegatecall, Staticcall, Callcode)

    def callback(self, info: TraversalInfo, inst_instance: ValueInstance, is_end: bool) -> None:
        if not info.function.is_runtime:
            return
        if not is_end:
            if isinstance(inst_instance.value, (Call, Delegatecall, Staticcall, Callcode)):
                if (
                    self.get_call_signature(inst_instance) == 0x81548319  # lock(bytes)
                    and (lock_bytes := self.get_call_args_member(inst_instance, 0)) is not None
                ) or (
                    self.get_call_signature(inst_instance) == 0x9CA17998  # lock(address,bytes)
                    and (lock_bytes := self.get_call_args_member(inst_instance, 1)) is not None
                    and (lock_address := self.get_call_args_member(inst_instance, 0)) is not None
                    and isinstance(lock_address.origin.value, Address)  # address is self
                ):
                    if (callback_selector := lock_bytes.function_signature) is not None:
                        self.callback_functions.add(
                            (callback_selector, info.contract.dispatcher[callback_selector].name)
                        )

    def get_internal_result(self) -> List[Tuple[int, Optional[str]]]:
        return list(self.callback_functions)

    def get_external_result(self) -> List:
        return []
