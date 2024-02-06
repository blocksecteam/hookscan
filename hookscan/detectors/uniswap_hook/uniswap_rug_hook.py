# NOTE THIS IS PROTOTYPE

from typing import Dict, List

from hookscan.components.constant import ConstantInt
from hookscan.components.evm_instructions import Call, Callcode
from hookscan.components.value import Value
from hookscan.core.instruction_instance import ValueInstance
from hookscan.core.traversal_info import TraversalInfo
from hookscan.detectors.base_detector import BaseDetector
from hookscan.detectors.detector_result import DetectorResult


class UniswapRugHook(BaseDetector):
    """Transfer to a controlled (by owner) address in a privilege function."""

    VULNERABILITY_DESCRIPTION = "possible rug-pull hook"

    def __init__(self) -> None:
        super().__init__()
        self._result: Dict[Value, DetectorResult] = {}
        self.callback_keys = (
            Call,
            Callcode,
        )

    def callback(self, info: TraversalInfo, inst_instance: ValueInstance, is_end: bool):
        if not info.function.is_runtime:
            return
        if is_end:
            if not info.is_protected:
                return  # rug function should be privileged
            for transfer_inst in self.get_all_hooked_instances(info):
                if isinstance(transfer_inst_value := transfer_inst.value, (Call, Callcode)):
                    if self.get_call_signature(transfer_inst) in {  # token transfer
                        0xA9059CBB,  # erc20 transfer(address,uint256)
                        0x23B872DD,  # erc20 transferFrom(address,address,uint256)
                        0x42842E0E,  # erc721 safeTransferFrom(address,address,uint256)
                        0xB88D4FDE,  # erc721 safeTransferFrom(address,address,uint256,bytes)
                        0x23B872DD,  # erc721 transferFrom(address,address,uint256)
                        0x2EB2C2D6,  # erc1155 safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)
                        0xF242432A,  # erc1155 safeTransferFrom(address,address,uint256,uint256,bytes)
                    } or not (  # native call: value == 0
                        isinstance(call_value := transfer_inst_value.operands[2], ConstantInt) and call_value.value == 0
                    ):
                        self._result[transfer_inst_value] = DetectorResult(
                            target=inst_instance, severity="medium", confidence="medium"
                        )

    def get_internal_result(self) -> List[DetectorResult]:
        return list(self._result.values())

    def get_external_result(self) -> List[DetectorResult]:
        return self.get_internal_result()
