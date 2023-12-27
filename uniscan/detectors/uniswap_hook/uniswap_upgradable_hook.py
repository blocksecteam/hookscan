from typing import Dict, List

from uniscan.components.evm_instructions import Delegatecall
from uniscan.components.memory_instructions import ABIDecodeFromCallData, ABIDecodeFromMemory
from uniscan.components.storage_instructions import StorageReadInst
from uniscan.components.value import Value
from uniscan.core.instruction_instance import ValueInstance
from uniscan.core.traversal_info import TraversalInfo
from uniscan.detectors.base_detector import BaseDetector
from uniscan.detectors.detector_result import DetectorResult


class UniswapUpgradableHook(BaseDetector):
    """Hook contracts are able to delegatecall to mutable addresses."""

    VULNERABILITY_DESCRIPTION = "containing delegate-call to mutable addresses"

    def __init__(self) -> None:
        super().__init__()
        self._result: Dict[Value, DetectorResult] = {}
        self.callback_keys = (Delegatecall,)

    def callback(self, info: TraversalInfo, inst_instance: ValueInstance, is_end: bool):
        if not info.function.is_runtime:
            return
        if not is_end:
            if (inst_value := inst_instance.value) is not None and isinstance(inst_value, Delegatecall):
                address_instance = inst_instance.operand_instances[1].origin
                if isinstance(
                    address_instance.value,
                    (StorageReadInst, ABIDecodeFromCallData, ABIDecodeFromMemory),  # mutable address
                ):
                    self._result[inst_value] = DetectorResult(target=inst_instance, severity="high", confidence="high")

    def get_internal_result(self) -> List[DetectorResult]:
        return list(self._result.values())

    def get_external_result(self) -> List[DetectorResult]:
        return self.get_internal_result()
