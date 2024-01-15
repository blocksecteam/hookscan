from typing import Dict, List

from hookscan.components.evm_instructions import Return
from hookscan.core.instruction_instance import ValueInstance
from hookscan.core.traversal_info import TraversalInfo
from hookscan.detectors.base_detector import BaseDetector
from hookscan.detectors.detector_result import DetectorResult


class UniswapPublicHook(BaseDetector):
    """Anyone can call hook functions.

    This detector enumerates all the hook functions (e.g. `beforeSwap`) that are not `view` and can be called by
        anyone without privilege validation.
    """

    VULNERABILITY_DESCRIPTION = "no constraints on callers of hook functions (pool manager only)"

    def __init__(self) -> None:
        super().__init__()
        self.callback_keys = (Return,)  # no need for callback, use random one to enable callback
        self.unsafe_hooks: Dict[int, DetectorResult] = {}  # {hook: result}

    def callback(self, info: TraversalInfo, inst_instance: ValueInstance, is_end: bool) -> None:
        if not info.function.is_runtime:
            return
        if not is_end:
            pass
        elif is_end and not self.terminated_by_revert(info):
            if not info.entry_point_function.mutable_or_payable:  # pyright: ignore
                return

            if (external_selector := info.current_function_selector) is not None:
                if external_selector not in {
                    # hooks at 3b724503d4c3fa4872ac0b4f9b12f694774224a4
                    0x43C4407E,  # afterDonate(address,(address,address,uint24,int24,address),uint256,uint256)
                    0x6FE7E6EB,  # afterInitialize(address,(address,address,uint24,int24,address),uint160,int24)
                    0x0E2059F5,  # afterModifyPosition(address,(address,address,uint24,int24,address),(int24,int24,int256),int256)
                    0xA5AA370A,  # afterSwap(address,(address,address,uint24,int24,address),(bool,int256,uint160),int256)
                    0x4DBB99A6,  # beforeDonate(address,(address,address,uint24,int24,address),uint256,uint256)
                    0xDC98354E,  # beforeInitialize(address,(address,address,uint24,int24,address),uint160)
                    0x0DBE5DBD,  # beforeModifyPosition(address,(address,address,uint24,int24,address),(int24,int24,int256))
                    0xB3F97F80,  # beforeSwap(address,(address,address,uint24,int24,address),(bool,int256,uint160))
                    # hooks at 06564d33b2fa6095830c914461ee64d34d39c305
                    0xE1B4AF69,  # afterDonate(address,(address,address,uint24,int24,address),uint256,uint256,bytes)
                    0xA910F80F,  # afterInitialize(address,(address,address,uint24,int24,address),uint160,int24,bytes)
                    0x30B7CDEF,  # afterModifyPosition(address,(address,address,uint24,int24,address),(int24,int24,int256),int256,bytes)
                    0xB47B2FB1,  # afterSwap(address,(address,address,uint24,int24,address),(bool,int256,uint160),int256,bytes)
                    0xB6A8B0FA,  # beforeDonate(address,(address,address,uint24,int24,address),uint256,uint256,bytes)
                    0x3440D820,  # beforeInitialize(address,(address,address,uint24,int24,address),uint160,bytes)
                    0xFE9A6F45,  # beforeModifyPosition(address,(address,address,uint24,int24,address),(int24,int24,int256),bytes)
                    0x575E24B4,  # beforeSwap(address,(address,address,uint24,int24,address),(bool,int256,uint160),bytes)
                    # other functions
                    0xAB6291FE,  # lockAcquired(bytes)
                    0x15C7AFB4,  # lockAcquired(address,bytes)
                }:
                    return
                if not info.is_protected:
                    if external_selector not in self.unsafe_hooks:
                        self.unsafe_hooks[external_selector] = DetectorResult(
                            target=info.entry_point_function,  # pyright: ignore
                            severity="high",
                            confidence="high",
                        )

    def get_internal_result(self) -> List[DetectorResult]:
        return list(self.unsafe_hooks.values())

    def get_external_result(self) -> List[DetectorResult]:
        return self.get_internal_result()
