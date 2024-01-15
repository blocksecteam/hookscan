import time
from typing import TYPE_CHECKING, Dict

from hookscan.components.contract import Contract
from hookscan.components.function import Function, FunctionType
from hookscan.components.instruction import CallInst, SwitchInst
from hookscan.utils.logger import runtime_logger

if TYPE_CHECKING:
    from hookscan.core.traversal_info import TraversalInfo


class TimeoutHandler:
    def __init__(
        self,
        start_time_per_round: float,
        start_time_dict: Dict[str, float],
        timeout_limit_per_round: float,
        timeout_limit_creation_part_per_round: float,
        has_timeout_all: bool,
        contract: Contract,
    ) -> None:
        assert timeout_limit_creation_part_per_round < timeout_limit_per_round
        self.contract = contract
        self.start_time_per_round = start_time_per_round
        self.start_time_dict = start_time_dict
        self.timeout_limit_per_round = timeout_limit_per_round
        self.timeout_limit_creation_part_per_round = timeout_limit_creation_part_per_round
        self.has_timeout_all = has_timeout_all
        self.left_time = 0
        self.timeout_limit_dict, self.has_timeout_dict = self.init_timeout_limit(
            timeout_limit_per_round - timeout_limit_creation_part_per_round
        )

        runtime_logger.info(f"timeout_limit_per_round: {self.timeout_limit_per_round}")
        runtime_logger.info(f"timeout_limit_creation_part_per_round: {self.timeout_limit_creation_part_per_round}")
        runtime_logger.info(f"timeout_limit_dict: {self.timeout_limit_dict}")
        runtime_logger.info(f"start_time_per_round: {self.start_time_per_round}")

    def init_timeout_limit(self, timeout_limit_per_round):
        timeout_limit_dict = {}
        has_timeout_dict = {}
        external_fallback_function_numbers = self.get_external_fallback_function_numbers()
        if external_fallback_function_numbers != 0:
            per_timeout_limit = (timeout_limit_per_round) / external_fallback_function_numbers
            runtime_logger.info(f"external_fallback_function_number: {external_fallback_function_numbers}")
            runtime_logger.info(f"timeout_limit_per_function: {per_timeout_limit}")
            for function_name, function in self.contract.runtime_functions_dict.items():
                if function.type == FunctionType.EXTERNAL or function.type == FunctionType.FALLBACK:
                    timeout_limit_dict[function_name] = per_timeout_limit
                    has_timeout_dict[function_name] = False
        return timeout_limit_dict, has_timeout_dict

    def init_info(self, info: "TraversalInfo"):
        self.info = info

    def is_timeout(self):
        now_time = time.thread_time()
        if not self.info.function.is_runtime:
            if now_time - self.start_time_per_round > self.timeout_limit_creation_part_per_round:
                runtime_logger.warning("timeout because of Creation Part")
                return True
            return False

        if now_time - self.start_time_per_round > self.timeout_limit_per_round:
            if not self.has_timeout_all:
                runtime_logger.warning("timeout because of all time")
                self.has_timeout_all = True
            return True

        if len(self.info.get_call_stack_functions()) > 0:
            first_function = self.info.get_call_stack_functions()[0]
            first_function_name = first_function.name

            if first_function.type == FunctionType.EXTERNAL or first_function.type == FunctionType.FALLBACK:
                if now_time - self.start_time_dict[first_function_name] > self.timeout_limit_dict[first_function_name]:
                    if not self.has_timeout_dict[first_function_name]:
                        runtime_logger.warning(f"timeout because of function: {first_function_name}")
                        self.has_timeout_dict[first_function_name] = True
                    return True
        return False

    def dynamic_update_timeout_limit_dict(self):
        def get_remain_external_function_number():
            number = 0
            for function_name in self.timeout_limit_dict.keys():
                if function_name.startswith("external_fun") and function_name not in self.info.has_done_function_list:
                    number += 1
            return number

        for function_name in self.timeout_limit_dict.keys():
            if function_name not in self.info.has_done_function_list and function_name.startswith("external_fun"):
                self.timeout_limit_dict[function_name] += self.left_time / get_remain_external_function_number()

    def _before_call(self, call_inst: CallInst, callee: Function, callee_name: str):
        if call_inst.basic_block.function.name == "__runtime" and (
            callee.type == FunctionType.EXTERNAL or callee.type == FunctionType.FALLBACK
        ):
            self.start_time_dict[callee_name] = time.thread_time()
            self.info.entry_point_function = callee
            if callee.type == FunctionType.EXTERNAL:
                assert self.info.path.__len__() == 5
                assert self.info.path[3].inst_instances.__len__() == 1 and isinstance(
                    self.info.path[3].inst_instances[0].value, SwitchInst
                )
                self.info.current_function_selector = self.info.path[3].condition_choose

            elif callee.type == FunctionType.FALLBACK:
                self.info.current_function_selector = "FALLBACK"

            runtime_logger.info(
                f"{callee_name} start detect, time limit: {round(self.timeout_limit_dict[callee_name],2)}"
            )
        return True

    def _after_call(self, call_inst: CallInst, callee: Function, callee_name: str):
        if call_inst.basic_block.function.name == "__runtime" and (
            callee.type == FunctionType.EXTERNAL or callee.type == FunctionType.FALLBACK
        ):
            time_used = time.thread_time() - self.start_time_dict[callee_name]
            self.info.entry_point_function = None
            self.info.current_function_selector = None
            runtime_logger.info(f"{callee_name} detect done, time used: {round(time_used,2)}")
            self.info.has_done_function_list.append(callee_name)
            consider_left_time = self.timeout_limit_dict[callee_name] - time_used
            if consider_left_time > 0:
                self.left_time += consider_left_time
                self.dynamic_update_timeout_limit_dict()
                self.left_time = 0

    def get_external_fallback_function_numbers(self):
        number = 0
        for _, function in self.contract.runtime_functions_dict.items():
            if function.type == FunctionType.FALLBACK or function.type == FunctionType.EXTERNAL:
                number += 1
        return number
