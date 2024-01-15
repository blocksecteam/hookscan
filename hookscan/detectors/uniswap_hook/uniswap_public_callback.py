from typing import Dict, List, MutableSet, Optional, Tuple

from hookscan.components.evm_instructions import Address, Caller, Eq, Return
from hookscan.core.instruction_instance import ValueInstance
from hookscan.core.traversal_info import TraversalInfo
from hookscan.detectors.base_detector import BaseDetector
from hookscan.detectors.detector_result import DetectorResult
from hookscan.detectors.uniswap_hook.uniswap_get_callback import UniswapGetCallback
from hookscan.utils.ordered_set import OrderedSet as set


class UniswapPublicCallback(BaseDetector):
    """For any callback functions that are called by lockAcquired using external calls,
        there should be an only-self check (no need for internal callback).

    This detector enumerates all callback functions given by UniswapGetCallback detector which lacks `onlySelf` check.
    """

    VULNERABILITY_DESCRIPTION = "no constraints on callers of callback function (self only)"

    def __init__(self) -> None:
        super().__init__()
        self.callback_keys = (Eq, Return)  # Return is to trigger callback() at end
        self.traversal_rounds_and_dependency = {0: (UniswapGetCallback,)}

    def traverse_start(self, info: TraversalInfo, current_round: int):
        super().traverse_start(info, current_round)
        if current_round == 0:
            hook_callbacks: MutableSet[Tuple[int, Optional[str]]] = set(info.all_res[UniswapGetCallback])
            self.hook_callbacks_selector: MutableSet[int] = set(selector for selector, _ in hook_callbacks)
            self.hook_callbacks_map: Dict[int, Optional[str]] = {selector: name for selector, name in hook_callbacks}
            self.result_for_all_callbacks: Dict[int, DetectorResult] = {}

    def callback(self, info: TraversalInfo, inst_instance: ValueInstance, is_end: bool) -> None:
        if not info.function.is_runtime:
            return
        if not isinstance((external_selector := info.current_function_selector), int):
            return

        if not is_end:
            if not isinstance(inst_instance.value, Eq) or len(inst_instance.operand_instances) != 2:
                return  # invalid instruction instance
            if external_selector not in self.hook_callbacks_selector:
                return  # not a callback function or has been checked

            op0_origin_value = inst_instance.operand_instances[0].origin.value
            op1_origin_value = inst_instance.operand_instances[1].origin.value
            if (isinstance(op0_origin_value, Caller) and isinstance(op1_origin_value, Address)) or (
                isinstance(op0_origin_value, Address) and isinstance(op1_origin_value, Caller)
            ):
                self.hook_callbacks_selector.remove(external_selector)
        elif is_end:
            if (
                external_selector not in self.result_for_all_callbacks
                and external_selector in self.hook_callbacks_map
                and info.entry_point_function.mutable_or_payable  # pyright: ignore
            ):
                self.result_for_all_callbacks[external_selector] = DetectorResult(
                    target=info.entry_point_function,  # pyright: ignore
                    severity="high",
                    confidence="high",
                )

    def get_internal_result(self) -> List[DetectorResult]:
        return [
            self.result_for_all_callbacks[selector]
            for selector in self.hook_callbacks_selector
            if selector in self.result_for_all_callbacks
        ]

    def get_external_result(self) -> List[DetectorResult]:
        return self.get_internal_result()
