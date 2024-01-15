import time
from collections import defaultdict
from typing import Any, Callable, Dict, List, MutableSet, Optional, Type, Union

from hookscan.components.contract import Contract
from hookscan.components.evm_instructions import Sload, Sstore, all_evm_instructions
from hookscan.components.instruction import (
    BranchInst,
    CallInst,
    ExtractReturnValue,
    Instruction,
    MathInst,
    PHINode,
    ReturnInst,
    SwitchInst,
    UnreachableInst,
    YulFuncInst,
)
from hookscan.components.memory_instructions import all_memory_instructions
from hookscan.components.protect_handler import ProtectHandler
from hookscan.components.storage_instructions import all_storage_instructions
from hookscan.components.timeout_handler import TimeoutHandler
from hookscan.components.yul_instructions import all_yul_instructions
from hookscan.core.traversal import Traversal
from hookscan.core.traversal_info import TraversalInfo
from hookscan.detectors.base_detector import BaseDetector
from hookscan.utils.logger import runtime_logger
from hookscan.utils.ordered_set import OrderedSet as set
from hookscan.yul_parser.yul_parser import parse_yul


class Hookscan:
    def __init__(
        self,
        std_out_json: Dict[str, Any],
        contract_name: Optional[str] = None,
        std_in_json: Optional[Dict[str, Any]] = None,
        only_run_not_protected: bool = False,
        timeout_limit_per_round: Optional[float] = None,
        timeout_limit_creation_part_per_round: Optional[float] = None,
    ) -> None:

        self.contract: Contract = self.generate_contract(std_out_json, contract_name, std_in_json)
        self._valid_keys = self._get_valid_keys()
        self.detector_instances: List[BaseDetector] = []
        self.original_detector_instances: List[BaseDetector] = []
        self.detector_classes: List[Type[BaseDetector]] = []
        self.callback_dict: Dict[Type[Instruction], List[Callable]] = defaultdict(list)
        self.traverse_event_registrants: List[BaseDetector] = []

        self.only_run_not_protected = only_run_not_protected
        if timeout_limit_per_round is None:
            timeout_limit_per_round = 60.0
        self.timeout_limit_per_round = timeout_limit_per_round
        if timeout_limit_creation_part_per_round is None:
            timeout_limit_creation_part_per_round = 3.0
        self.timeout_limit_creation_part_per_round = timeout_limit_creation_part_per_round

    def generate_contract(
        self, std_out_json: Dict[str, Any], target_contract_name: Optional[str], std_in_json: Optional[Dict[str, Any]]
    ) -> Contract:
        tmp_contract: Optional[Contract] = None
        contract_d = std_out_json["contracts"]
        for file_name, d in contract_d.items():
            for tmp_contract_name, dd in d.items():
                if target_contract_name is not None and target_contract_name != tmp_contract_name:
                    continue
                yul = dd["ir"]
                if yul == "":
                    continue
                if tmp_contract is not None:
                    if target_contract_name is None:
                        raise Exception("multi contracts found, please specify the contract name")
                    else:
                        raise Exception(
                            f"multi contracts with the same name: {tmp_contract.file_name}:{tmp_contract.contract_name} {file_name}:{tmp_contract_name}"
                        )
                tmp_contract = parse_yul(yul)
                tmp_contract.initialize(
                    yul=yul,
                    std_in_json=std_in_json,
                    std_out_json=std_out_json,
                    file_name=file_name,
                    contract_name=tmp_contract_name,
                )
        assert tmp_contract is not None, "no contract found"
        return tmp_contract

    def check_all_detectors_callback_is_valid(self):
        all_detectors_callback = set()
        for detector_instance in self.detector_instances:
            all_detectors_callback.update(detector_instance.callback_keys)
        for key1 in all_detectors_callback:
            for key2 in all_detectors_callback:
                if key1 == key2:
                    continue
                assert not (issubclass(key1, key2) or issubclass(key2, key1))

    def _register_dependency_detectors_recursive(self):
        add_detectors = False
        for detector_instance in self.detector_instances:
            for dependency_detector_types in detector_instance.traversal_rounds_and_dependency.values():
                for dependency_detector_type in dependency_detector_types:
                    if dependency_detector_type not in self.detector_classes:
                        dependency_detector_instance = dependency_detector_type()
                        self.detector_instances.append(dependency_detector_instance)
                        self.detector_classes.append(dependency_detector_type)
                        add_detectors = True
        if add_detectors:
            self._register_dependency_detectors_recursive()
        else:
            return

    def register_detectors(self, detector_classes: List[Type[BaseDetector]]):
        assert len(self.detector_instances) == 0, "detector already registered"
        assert len(detector_classes) == len(set(detector_classes)), "duplicated registers"

        for detector_cls in detector_classes:
            instance = detector_cls()
            self.original_detector_instances.append(instance)
            self.detector_instances.append(instance)
            self.detector_classes.append(detector_cls)

        self._register_dependency_detectors_recursive()
        self.check_all_detectors_callback_is_valid()

    def init_detector_relative_rounds(self, detector_relative_rounds: Dict[BaseDetector, int]):
        for detector_instance in self.detector_instances:
            detector_relative_rounds[detector_instance] = -1

    def check_dependency_satisfied(
        self,
        detector_instance: BaseDetector,
        has_done_detector: MutableSet[BaseDetector],
        detector_relative_rounds: Dict[BaseDetector, int],
    ):
        detector_dependency = detector_instance.traversal_rounds_and_dependency[
            detector_relative_rounds[detector_instance] + 1
        ]
        has_done_detector_type: MutableSet[Type[BaseDetector]] = set()
        for detector_instance in has_done_detector:
            has_done_detector_type.add(type(detector_instance))
        if set(detector_dependency).issubset(has_done_detector_type):
            return True
        else:
            return False

    def dynamic_register_detectors(
        self,
        has_done_detector: MutableSet[BaseDetector],
        detector_relative_rounds: Dict[BaseDetector, int],
    ):
        self.callback_dict = defaultdict(list)
        self.traverse_event_registrants = []
        detector_this_round = []
        for detector_instance in self.detector_instances:
            if detector_instance in has_done_detector:
                continue
            if self.check_dependency_satisfied(detector_instance, has_done_detector, detector_relative_rounds):
                detector_this_round.append(detector_instance)

        for detector_instance in detector_this_round:
            detector_relative_rounds[detector_instance] += 1
            for key in detector_instance.callback_keys:
                assert key in self._valid_keys
                self.callback_dict[key].append(detector_instance.callback)
            if detector_instance.register_traverse_event:
                self.traverse_event_registrants.append(detector_instance)

        return detector_this_round

    def init_result(self) -> Dict:
        result = {
            "detection_results": {},
            "info": {},
        }
        result["info"]["contract_name"] = self.contract.contract_name
        result["info"]["is_timeout"] = False
        result["info"]["time_used"] = 0
        result["info"]["traversal_rounds"] = 0

        return result

    def update_result(self, result, all_time_used, has_timeout_dict):
        result["info"]["time_used"] = all_time_used
        result["info"]["traversal_rounds"] += 1
        result["info"]["is_timeout"] = (
            True if any(x is True for x in has_timeout_dict.values()) or result["info"]["is_timeout"] is True else False
        )

    def finalize_result(self, result, all_res_external, str_key):
        if str_key:
            result["detection_results"] = {k.__name__: v for k, v in all_res_external.items()}
        else:
            result["detection_results"] = all_res_external

    def detect(self, str_key: bool = False) -> Dict[Union[Type[BaseDetector], str], Any]:
        result = self.init_result()
        all_res_internal = {}
        all_res_external = {}
        traversal_round = 0
        all_time_used = 0
        has_done_detector = set()
        detector_relative_rounds: Dict[BaseDetector, int] = {}
        self.init_detector_relative_rounds(detector_relative_rounds)
        runtime_logger.info("******start detect******")
        runtime_logger.info(f"detect contract name: {self.contract.contract_name}")
        while True:
            runtime_logger.info(f"traversal_round: {traversal_round}")
            traversal_round += 1
            if has_done_detector == set(self.detector_instances):
                runtime_logger.info(f"all time used {all_time_used}")  # noqa: F821
                runtime_logger.info("******detect done******")
                self.finalize_result(result, all_res_external, str_key)
                return result
            detector_this_round: List[BaseDetector] = self.dynamic_register_detectors(
                has_done_detector, detector_relative_rounds
            )
            runtime_logger.info(f"detector_this_round: {detector_this_round}")
            timeout_handler = TimeoutHandler(
                start_time_per_round=time.thread_time(),
                start_time_dict={},
                timeout_limit_per_round=self.timeout_limit_per_round,
                timeout_limit_creation_part_per_round=self.timeout_limit_creation_part_per_round,
                has_timeout_all=False,
                contract=self.contract,
            )

            for func in (self.contract.creation, self.contract.runtime):
                info = TraversalInfo(
                    contract=self.contract,
                    function=func,
                    detector_relative_rounds=detector_relative_rounds,
                    all_res=all_res_internal,
                    has_done_function_list=[],
                    entry_point_function=None,
                    protect_handler=ProtectHandler(),
                    timeout_handler=timeout_handler,
                    only_run_not_protected=self.only_run_not_protected,
                    is_end=False,
                )
                Traversal(self.traverse_event_registrants, self.callback_dict, info=info).traverse()

                if func == self.contract.creation:
                    creation_done_time = time.thread_time()
                    runtime_logger.info(
                        f"time used in creation part {time.thread_time()-timeout_handler.start_time_per_round}"
                    )
                elif func == self.contract.runtime:
                    runtime_logger.info(
                        f"time used in runtime part {time.thread_time()-creation_done_time}"  # pyright: ignore
                    )

            for instance in self.detector_instances:
                if (
                    detector_relative_rounds[instance] == max(instance.traversal_rounds_and_dependency.keys())
                    and instance not in has_done_detector
                ):
                    has_done_detector.add(instance)
                    assert hasattr(instance, "get_internal_result") or hasattr(instance, "get_external_result")
                    if hasattr(instance, "get_internal_result"):
                        res_internal = instance.get_internal_result()
                        all_res_internal[type(instance)] = res_internal
                    if hasattr(instance, "get_external_result") and instance in self.original_detector_instances:
                        res_external = instance.get_external_result()
                        all_res_external[type(instance)] = res_external

            runtime_logger.info(
                f"time used this round {time.thread_time()-timeout_handler.start_time_per_round}"
            )  # noqa: F821
            all_time_used += time.thread_time() - timeout_handler.start_time_per_round
            self.update_result(result, all_time_used, timeout_handler.has_timeout_dict)

    def _get_valid_keys(self) -> MutableSet[Type[Instruction]]:
        res: MutableSet[Type[Instruction]] = set()
        for inst_cls in (
            ReturnInst,
            CallInst,
            ExtractReturnValue,
            PHINode,
            BranchInst,
            SwitchInst,
            UnreachableInst,
            MathInst,
        ):
            res.add(inst_cls)
        for inst_cls in all_evm_instructions:
            res.add(inst_cls)
        for inst_cls in all_yul_instructions:
            res.add(inst_cls)
        for inst_cls in all_memory_instructions:
            res.add(inst_cls)
        for inst_cls in all_storage_instructions:
            res.add(inst_cls)
        res.remove(Sstore)
        res.remove(Sload)

        res.add(YulFuncInst)

        return res
