from typing import Dict, List

from hookscan.components.evm_instructions import Selfdestruct
from hookscan.components.value import Value
from hookscan.core.instruction_instance import ValueInstance
from hookscan.core.traversal_info import TraversalInfo
from hookscan.detectors.base_detector import BaseDetector
from hookscan.detectors.detector_result import DetectorResult


class UniswapSuicidalHook(BaseDetector):
    """No self-destruct is allowed, even with privilege validation."""

    VULNERABILITY_DESCRIPTION = "containing self-destruct"

    def __init__(self) -> None:
        super().__init__()
        self._result: Dict[Value, DetectorResult] = {}
        self.callback_keys = (Selfdestruct,)

    def callback(self, info: TraversalInfo, inst_instance: ValueInstance, is_end: bool):
        if not info.function.is_runtime:
            return
        if not is_end:
            if (inst_value := inst_instance.value) is not None and isinstance(inst_value, Selfdestruct):
                self._result[inst_value] = DetectorResult(target=inst_instance, severity="medium", confidence="high")

    def get_internal_result(self) -> List[DetectorResult]:
        return list(self._result.values())

    def get_external_result(self) -> List[DetectorResult]:
        return self.get_internal_result()
