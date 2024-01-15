import sys
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Type, Union

from hookscan.components.basic_block import BasicBlock
from hookscan.components.constant import Constant, ConstantInt
from hookscan.components.evm_instructions import (
    Add,
    Address,
    And,
    Call,
    Callcode,
    Caller,
    Callvalue,
    Delegatecall,
    Eq,
    Gt,
    Iszero,
    Keccak256,
    Lt,
    Mstore,
    Number,
    Origin,
    Returndatacopy,
    Returndatasize,
    Sgt,
    Sload,
    Slt,
    Staticcall,
    Timestamp,
)
from hookscan.components.instruction import (
    AbstractEVMInst,
    BranchInst,
    CallInst,
    ExtractReturnValue,
    Instruction,
    PHINode,
    ReturnInst,
    SwitchInst,
    UnreachableInst,
    YulFuncInst,
)
from hookscan.components.memory_instructions import (
    ABIDecodeFromCallData,
    ABIEncode,
    CalldataArrayLength,
    Concat,
    ConvertReference,
    CopyArray,
    ExtractReturnData,
    MemoryArrayLength,
)
from hookscan.components.storage_instructions import StorageArrayLength, StorageReadInst
from hookscan.components.type_convert_instruction import TypeConvertInstruction
from hookscan.components.value import Value
from hookscan.components.yul_instructions import Datasize, Loadimmutable
from hookscan.core.instruction_instance import ValueInstance
from hookscan.core.traversal_info import CallInfo, PathNode, TraversalInfo
from hookscan.detectors.base_detector import BaseDetector
from hookscan.utils.flatten_key_mapping import get_key
from hookscan.utils.logger import runtime_logger
from hookscan.utils.ordered_set import OrderedSet as set
from hookscan.utils.selector_table import not_consider_protect_standard_selector
from hookscan.utils.two_args_calldataptr import is_two_args_calldata_ptr
from hookscan.utils.type_parser import TypeParser

sys.setrecursionlimit(10000)


@dataclass
class Constraint:
    condition: ValueInstance
    is_eq: bool
    case_value: int
    condition_key = None
    solve_result: Optional[bool] = None

    def __post_init__(self):
        self._normalize()
        self.condition_key = get_key(self.condition)
        self._try_solve()

    @staticmethod
    def _is_bool_condition(condition: Value):
        assert isinstance(condition, Value)
        if not isinstance(condition, AbstractEVMInst):
            return False

        if isinstance(condition, (Lt, Gt, Slt, Sgt, Eq, Iszero)):
            return True

        if isinstance(condition, And):
            v1 = condition.arguments[1]
            if not isinstance(v1, ConstantInt):
                return False
            return v1.value == 1

        return False

    def _normalize(self):
        self.condition = self.condition.origin
        if isinstance(self.condition.value, Iszero):
            assert self.case_value in (0, 1)
            self.condition = self.condition.operand_instances[0]
            self.is_eq = not (self.is_eq ^ self.case_value)
            self.case_value = 0
            return self._normalize()
        elif self._is_bool_condition(self.condition.value) and not self.is_eq:
            assert self.case_value in (0, 1)
            self.is_eq = True
            self.case_value = 1 - self.case_value
            return self._normalize()
        elif isinstance(self.condition.value, Eq):
            for i in range(2):
                if isinstance(self.condition.operand_instances[i].origin.value, ConstantInt):
                    assert self.case_value in (0, 1)
                    cst = self.condition.operand_instances[i].origin.value.value  # pyright: ignore
                    self.condition = self.condition.operand_instances[1 - i].origin
                    self.is_eq = not (self.is_eq ^ self.case_value)
                    self.case_value = cst
                    return self._normalize()

    def _try_solve(self):
        if isinstance(self.condition.value, ConstantInt):
            self.solve_result = self.is_eq == (self.condition.value.value == self.case_value)
        elif isinstance(self.condition.value, Eq):
            assert self.is_eq
            assert self.case_value in (0, 1)
            a, b = self.condition.operand_instances
            a = a.origin
            b = b.origin

            if get_key(a) == get_key(b):
                self.solve_result = bool(self.case_value)


class Traversal:
    def __init__(
        self,
        traverse_event_registrants: List["BaseDetector"],
        callback_dict: Dict[Type[Instruction], List[Callable]],
        info: TraversalInfo,
    ):
        self.traverse_event_registrants = traverse_event_registrants
        self.callback_dict = callback_dict
        self.info = info
        self.init_info_for_handle()

    def init_info_for_handle(self):
        self.info.timeout_handler.init_info(self.info)
        self.info.protect_handler.init_info(self.info)

    def traverse(self):
        for detector in self.traverse_event_registrants:
            detector.traverse_start(self.info, self.info.detector_relative_rounds[detector])
        self.dfs(self.info.function.entry_point)
        for detector in self.traverse_event_registrants:
            detector.traverse_stop(self.info, self.info.detector_relative_rounds[detector])

    # find the exact classes in callback_dict, return None if not found
    def get_exact_key_in_callback_dict(self, inst_instance: ValueInstance) -> Union[Type[Instruction], None]:
        for key in self.callback_dict.keys():
            if type(inst_instance.value) == key:
                return key
        return None

    def trigger_callback(self, inst_instance: ValueInstance, is_end: bool, path_node_index: int, inst_index: int):
        if not is_end:
            assert not self.info.is_end
            exact_key = self.get_exact_key_in_callback_dict(inst_instance)

            if exact_key is not None:
                self.info.trigger_index_list.append((path_node_index, inst_index))
            else:
                return
            for callback in self.callback_dict[exact_key]:
                try:
                    callback(self.info, inst_instance, is_end)
                except NotImplementedError as e:
                    if e.args != ():
                        runtime_logger.warning(f"[Callback] Raised NotImplemented Error: {e}")

        if is_end:
            assert not self.info.is_end
            self.info.is_end = True
            assert isinstance(inst_instance.value, UnreachableInst)
            has_trigger_detector_set = set()
            for trigger_path_index, trigger_inst_index in reversed(self.info.trigger_index_list):
                trigger_path_node = self.info.path[trigger_path_index]
                trigger_inst_index -= (
                    trigger_path_node.start_index
                )  # if start_index is not 0, then inst_instance recorded by path_node starts from start_index
                trigger_inst_instance = trigger_path_node.inst_instances[trigger_inst_index]
                exact_key = self.get_exact_key_in_callback_dict(trigger_inst_instance)
                assert exact_key in self.callback_dict

                for callback in self.callback_dict[exact_key]:
                    if callback in has_trigger_detector_set:
                        continue
                    else:
                        try:
                            callback(self.info, None, is_end)
                        except NotImplementedError as e:
                            if e.args != ():
                                runtime_logger.warning(f"[Callback] Raised NotImplemented Error: {e}")

                        has_trigger_detector_set.add(callback)
            self.info.is_end = False

    def update_zero_value(self, inst_instance: ValueInstance):
        inst = inst_instance.value
        if not (
            isinstance(inst, YulFuncInst)
            and inst.name.startswith("zero_value_for_split_")
            and not inst.name.endswith("memory_ptr")
        ):
            return
        tmp_ConstantInt = ConstantInt(inst_instance.value.id_group, 0)
        origin = self.info._get_instance(tmp_ConstantInt)
        inst_instance.propagate_from(origin)  # pyright: ignore

    def create_inst_instance(self, inst: Instruction, pre_bb=None, path_node=None):
        inst_instance = ValueInstance(inst, path_node=path_node, info=self.info)
        if isinstance(inst, ExtractReturnValue):
            _call_info_index = self.info.call_info_index_list[-1]
            _call_info = self.info.path[_call_info_index].call_info
            assert not _call_info.is_call  # pyright: ignore
            origin = _call_info.instances[inst.return_index]  # pyright: ignore
            inst_instance.propagate_from(origin)
        elif isinstance(inst, PHINode):
            assert pre_bb is not None
            _operand = inst.get_value_from_predecessor(pre_bb)
            origin = self.info._get_instance(_operand, user_phi=inst)
            inst_instance.propagate_from(origin)  # pyright: ignore
        else:
            self.update_operand_instances(inst_instance, path_node=path_node, info=self.info)  # pyright: ignore
            self.update_zero_value(inst_instance)
            self.update_type_convert(inst_instance)
            self.update_cleanup(inst_instance)
            self.update_taint(inst_instance)
            self.update_abi_encode(inst_instance)
            self.update_call(inst_instance)
            self.update_returndata(inst_instance)
            self.after_update_taint(inst_instance)
        return inst_instance

    def is_from_loop(self, bb: BasicBlock, loop_entry_pre_bb: Optional[BasicBlock]):
        return (
            loop_entry_pre_bb is not None
            # NOTE exit_point of loop tail_bb can't belong to sub loop even if it has sub loop
            and loop_entry_pre_bb.current_loop_entry is not None
            and loop_entry_pre_bb.current_loop_entry == bb.current_loop_entry
        )

    def dfs(  # noqa C901
        self,
        bb: BasicBlock,
        start_index: int = 0,
        *,
        pre_bb: Optional[BasicBlock] = None,
        last_fork_constraints: Optional[List[Constraint]] = None,
        loop_entry_pre_bb: Optional[BasicBlock] = None,
        real_condition_choose: Optional[bool] = None,
    ):
        if self.info.timeout_handler.is_timeout():
            return
        if self.info.only_run_not_protected and self.info.is_protected:
            return

        if (
            bb.is_loop_entry
            and bb.loop_compare is None
            # NOTE loop_entry_pre_bb has not been updated currently, so use pre_bb
            and self.is_from_loop(bb, pre_bb)
        ):
            # NOTE for loops without loop_compare, do not enter loop again
            return
        if len(self.info.path) == 0:
            path_node = PathNode(bb, start_index=start_index)
        else:
            path_node = PathNode(
                bb,
                start_index=start_index,
                detector_info_dict=self.info.path[-1].detector_info_dict.copy(),
            )
        path_node._last_fork_constraints = last_fork_constraints
        self.info.path.append(path_node)
        current_path_index = len(self.info.path) - 1
        self.info._path_node_stack[bb][start_index].append(path_node)

        self.info.protect_handler.add_protect_index_list(real_condition_choose)
        if bb.is_loop_entry:
            assert loop_entry_pre_bb is None
            loop_entry_pre_bb = pre_bb

        for i in range(start_index, len(bb.instructions)):
            inst = bb.instructions[i]
            inst_instance = self.create_inst_instance(inst, pre_bb=pre_bb, path_node=path_node)
            path_node.inst_instances.append(inst_instance)
            path_node.current_index = i
            self.trigger_callback(inst_instance, False, current_path_index, path_node.current_index)
            if isinstance(inst, CallInst):
                callee_name = inst.called_function.name
                callee = inst.called_function
                if self.info.timeout_handler._before_call(inst, callee, callee_name) is False:
                    break
                # NOTE recursive into same function for many times, stop the path
                if self.info._recursive_call_count_dict[callee] >= 2:
                    break
                # NOTE don't record last_fork_constraints, it is only used for the end of fork and the beginning of the next bb
                path_node.call_info = CallInfo(
                    is_call=True,
                    inst_instance=inst_instance,
                    return_bb=bb,
                    return_index=i + 1,
                    return_pre_bb=pre_bb,
                    return_loop_entry_pre_bb=loop_entry_pre_bb,
                )
                self.info.call_info_index_list.append(current_path_index)
                self.info.call_index_stack.append(current_path_index)
                self.info._recursive_call_count_dict[callee] += 1
                # NOTE cross-function don't set pre_bb
                self.dfs(callee.entry_point, 0, pre_bb=None, loop_entry_pre_bb=loop_entry_pre_bb)
                self.info._recursive_call_count_dict[callee] -= 1
                self.info.timeout_handler._after_call(inst, callee, callee_name)
                break
        else:
            if isinstance(bb.terminator, ReturnInst):
                inst = bb.terminator
                last_call_info = self.info.get_last_call_info()
                path_node.call_info = CallInfo(
                    is_call=False, inst_instance=self.info.current_path_node.inst_instances[-1]
                )
                self.info.call_info_index_list.append(current_path_index)
                popped_call_index = self.info.call_index_stack.pop()
                assert self.info.path[popped_call_index].call_info.is_call
                self.info._recursive_call_count_dict[inst.basic_block.function] -= 1
                self.dfs(
                    bb=last_call_info.return_bb,
                    start_index=last_call_info.return_index,
                    pre_bb=last_call_info.return_pre_bb,
                    loop_entry_pre_bb=last_call_info.return_loop_entry_pre_bb,
                )
                self.info.call_index_stack.append(popped_call_index)
                self.info._recursive_call_count_dict[inst.basic_block.function] += 1

            else:
                if len(bb.successors) > 1:
                    self.info.fork_index_list.append(current_path_index)

                terminator_instance = self.info.current_inst_instance
                assert terminator_instance.value == bb.terminator

                if isinstance(bb.terminator, BranchInst):

                    # NOTE consider for loop not enter may miss some permission check, cause fp. Here we fix for loop to go through (unless unsat at first time). Missing some paths should only cause fn (acceptable)
                    if bb.is_loop_compare:
                        from_loop = self.is_from_loop(bb, loop_entry_pre_bb)
                        if bb.is_loop_entry:
                            skip_true_successor = from_loop
                            skip_false_successor = not from_loop
                        else:
                            skip_true_successor = not from_loop
                            skip_false_successor = from_loop
                        loop_entry_pre_bb = None
                    else:
                        skip_true_successor = False
                        skip_false_successor = False

                    if bb.is_do_while_compare:
                        from_loop = self.is_from_loop(bb, loop_entry_pre_bb)
                        if not from_loop:
                            loop_entry_pre_bb = None

                    if bb.terminator.is_conditional:
                        condition = terminator_instance.operand_instances[0].origin
                        for is_eq in (False, True):
                            if not is_eq and skip_true_successor:
                                continue
                            if is_eq and skip_false_successor:
                                continue
                            constraints = [Constraint(condition, is_eq, 0)]
                            if not self.is_violate_constraints(constraints):
                                path_node.condition_choose = not is_eq
                                self.dfs(
                                    bb.terminator.get_successor(
                                        when=(not is_eq)
                                    ),  # not is_eq is the actual path in source code
                                    0,
                                    pre_bb=bb,
                                    last_fork_constraints=constraints,
                                    loop_entry_pre_bb=loop_entry_pre_bb,
                                    real_condition_choose=(not is_eq),
                                )
                    else:
                        self.dfs(
                            bb.terminator.get_successor(),
                            0,
                            pre_bb=bb,
                            loop_entry_pre_bb=loop_entry_pre_bb,
                        )
                elif isinstance(bb.terminator, SwitchInst):
                    condition = terminator_instance.operand_instances[0].origin
                    default_constraints = []
                    for case, succ in bb.terminator.case_to_successor.items():
                        assert isinstance(case, ConstantInt)
                        case_value = case.value
                        constraints = [Constraint(condition, True, case_value)]
                        if not self.is_violate_constraints(constraints):
                            path_node.condition_choose = case.value
                            self.dfs(
                                succ,
                                0,
                                pre_bb=bb,
                                last_fork_constraints=constraints,
                                loop_entry_pre_bb=loop_entry_pre_bb,
                                real_condition_choose=(case_value != 0),
                            )
                        default_constraints.append(Constraint(condition, False, case_value))
                    default_successor = bb.terminator.default_successor
                    if not isinstance(
                        default_successor.instructions[0], UnreachableInst
                    ) and not self.is_violate_constraints(default_constraints):
                        path_node.condition_choose = "default"
                        self.dfs(
                            default_successor,
                            0,
                            pre_bb=bb,
                            last_fork_constraints=default_constraints,
                            loop_entry_pre_bb=loop_entry_pre_bb,
                            real_condition_choose=True,
                        )

                else:
                    self.trigger_callback(
                        inst_instance, True, current_path_index, path_node.current_index
                    )  # NOTE This is the end of the path, trigger the callback again
                    assert isinstance(bb.terminator, UnreachableInst)

        self.pop_all(bb, start_index, path_node)

    def pop_all(self, bb, start_index, path_node):
        current_path_index = len(self.info.path) - 1
        for list_ in [
            self.info.fork_index_list,
            self.info.call_info_index_list,
            self.info.call_index_stack,
            self.info.loop_index_stack,
        ]:
            if len(list_) != 0 and list_[-1] >= current_path_index:
                popped_index = list_.pop()
                assert popped_index == current_path_index
            # should be only one
            assert len(list_) == 0 or list_[-1] < current_path_index, "multi current index in list"

        # pop trigger_index_list, pop all index triggered in current path_node
        while len(self.info.trigger_index_list) != 0:
            (trigger_path_index, trigger_inst_index) = self.info.trigger_index_list[-1]
            if trigger_path_index == current_path_index and trigger_inst_index >= start_index:
                self.info.trigger_index_list.pop()
            else:
                break

        self.info.protect_handler.pop_protect()

        self.info.path.pop()
        self.info._path_node_stack[bb][start_index].pop()

    def update_operand_instances(self, instance: ValueInstance, path_node: PathNode = None, info: TraversalInfo = None):
        inst = instance.value
        assert not isinstance(inst, (ExtractReturnValue, PHINode))
        instance.operand_instances = [
            self.info._get_instance(operand, path_node=path_node, info=info) for operand in inst.operands
        ]

    def after_update_taint(self, instance: ValueInstance):
        inst = instance.value
        self.add_standard_selector_call_taint(instance)
        if isinstance(inst, (Call, Staticcall, Delegatecall, Callcode)):
            selector = instance.function_signature
            if selector in not_consider_protect_standard_selector.values():
                instance.taints.add("_is_not_consider_protect_standard_returndata")
                if isinstance(inst, (Call, Callcode)):
                    instance.operand_instances[5].taints.add("_is_not_consider_protect_standard_returndata")
                elif isinstance(inst, (Staticcall, Delegatecall)):
                    instance.operand_instances[4].taints.add("_is_not_consider_protect_standard_returndata")
        elif isinstance(inst, Keccak256):
            if "calldata" in instance.taints:
                instance.taints.add("_keccak256_after_calldata")

    def update_taint(self, instance: ValueInstance):
        inst = instance.value
        assert isinstance(inst, Instruction)

        # NOTE CallInst and ReturnInst itself has no taint, the taint of args and rets is in CallInfo
        # NOTE TypeConvertInstruction has been processed
        if isinstance(inst, (CallInst, ReturnInst)):
            return

        instance.taints = set()

        # Can't directly add taint on the vi that appears at the beginning of constantInt,
        # which will cause some constants that do not exist in the source code be tainted
        if isinstance(instance.origin.value, ConstantInt):
            instance.taints.add("_constant")

        elif isinstance(inst, Address):
            instance.taints.add("_address")

        elif isinstance(inst, Origin):
            instance.taints.add("origin")

        elif isinstance(inst, Callvalue):
            instance.taints.add("_callvalue")

        elif (
            isinstance(instance.origin.value, Staticcall)
            and isinstance(instance.origin.operand_instances[1].value, Constant)
            and instance.origin.operand_instances[1].value.value == 1
        ):
            instance.taints.add("_ecrecover")

        elif isinstance(inst, Caller):
            instance.taints.add(instance)
            instance.taints.add("caller")

        elif isinstance(inst, YulFuncInst) and inst.name.startswith("constant"):
            instance.taints.add("_constant")

        elif isinstance(inst, Loadimmutable):
            instance.taints.add("_loadimmutable")

        elif isinstance(inst, (StorageReadInst, Sload)):
            instance.taints.add("_storageread")

        elif isinstance(inst, (Concat, ConvertReference, CopyArray)) and "_storage" in inst.type_str:
            instance.taints.add("_storageread")

        if isinstance(inst, Keccak256) and (
            "calldata" in instance.operand_instances[0].taints or "calldata" in instance.operand_instances[1].taints
        ):
            instance.taints.add("_keccak256_after_calldata")

        elif isinstance(inst, (StorageArrayLength, MemoryArrayLength, CalldataArrayLength)):
            instance.taints.add("_array_length")

        elif isinstance(inst, Timestamp):
            instance.taints.add("timestamp")

        elif isinstance(inst, Number):
            instance.taints.add("number")

        elif isinstance(inst, Eq):
            instance.operand_instances[0].origin.taints.add("eq")
            instance.operand_instances[1].origin.taints.add("eq")

        # add taint from calldata
        elif isinstance(inst, ABIDecodeFromCallData):
            instance.taints.add(instance)
            instance.taints.add("calldata")

        # taint from return data
        elif isinstance(inst, ExtractReturnData):
            instance.taints.add("returndata")

        elif isinstance(inst, AbstractEVMInst) and (inst.name == "staticcall" or inst.name == "delegatecall"):
            instance.taints.add("returndata")
            instance.operand_instances[4].taints.add("returndata")

        elif isinstance(inst, AbstractEVMInst) and (inst.name == "call" or inst.name == "callcode"):
            instance.taints.add("returndata")
            instance.operand_instances[5].taints.add("returndata")

        elif isinstance(inst, AbstractEVMInst) and inst.name == "returndatacopy":
            instance.taints.add("returndata")

        for operand_instance in instance.operand_instances:
            if operand_instance is not None:
                _taints = operand_instance.taints
                instance.taints.update(_taints)

    def add_standard_selector_call_taint(self, inst_instance: ValueInstance):
        if isinstance(inst_instance.value, Staticcall):
            if inst_instance.function_signature == 0x6352211E:
                inst_instance.operand_instances[4].taints.add("_high_level_call_ownerof")
            elif inst_instance.function_signature == 0xE985E9C5:
                inst_instance.operand_instances[4].taints.add("_high_level_call_isApprovedForAll")
            elif inst_instance.function_signature == 0x081812FC:
                inst_instance.operand_instances[4].taints.add("_high_level_call_getApproved")

    def update_type_convert(self, inst_instance: ValueInstance):
        inst = inst_instance.value
        if not isinstance(inst, TypeConvertInstruction):
            return
        arg_instance = inst_instance.operand_instances[0]
        inst_instance.propagate_from(arg_instance)
        inst_instance.type_str = inst.to_type_str

    def update_cleanup(self, inst_instance: ValueInstance):
        inst = inst_instance.value
        if not (isinstance(inst, YulFuncInst) and inst.name.startswith("cleanup")):
            return
        arg_instance = inst_instance.operand_instances[0]
        inst_instance.propagate_from(arg_instance)
        inst_instance.type_str = inst.name[len("cleanup") + 1 :]

    def update_returndata(self, inst_instance: ValueInstance):
        inst = inst_instance.value
        if not isinstance(inst, (ExtractReturnData, Returndatacopy)):
            return
        last_evm_call_instance = self._find_last_evm_call_instance()
        if last_evm_call_instance is not None:
            if isinstance(inst, ExtractReturnData):
                inst_instance.taints.update(last_evm_call_instance.taints)
            else:
                inst_instance.operand_instances[0].taints.update(last_evm_call_instance.taints)

    def _find_last_evm_call_instance(self):
        for path_node in reversed(self.info.path):
            for inst_instance in reversed(path_node.inst_instances):
                if isinstance(inst_instance.value, (Call, Staticcall, Delegatecall, Callcode)):
                    return inst_instance
        return None

    def update_call(self, inst_instance: ValueInstance):
        inst = inst_instance.value
        if not isinstance(inst, (Call, Staticcall, Delegatecall, Callcode)):
            return
        if isinstance(inst, (Call, Callcode)):
            call_offset_instance = inst_instance.operand_instances[3]
        else:
            call_offset_instance = inst_instance.operand_instances[2]
        encode_ptr = self._find_encode_ptr(call_offset_instance)
        if encode_ptr is not None:
            inst_instance.taints.update(encode_ptr.taints)
            inst_instance.call_args = encode_ptr.call_args
            inst_instance.function_signature = encode_ptr.function_signature

    def update_abi_encode(self, inst_instance: ValueInstance):
        inst = inst_instance.value
        if not (isinstance(inst, ABIEncode) and not inst.is_packed):
            return
        inst_instance.call_args = self._record_call_args(inst_instance)
        inst_instance.function_signature = self._record_call_signature(inst_instance)
        # record in allocate instruction
        encode_ptr = self._find_encode_ptr(inst_instance)
        if encode_ptr is not None:
            encode_ptr.taints.update(inst_instance.taints)
            encode_ptr.call_args = inst_instance.call_args
            encode_ptr.function_signature = inst_instance.function_signature

    def _find_encode_ptr(self, inst_instance: ValueInstance):
        if isinstance(inst_instance.origin.value, ABIEncode) and not inst_instance.origin.value.is_packed:
            return self._find_encode_ptr(inst_instance.origin.operand_instances[0])
        elif isinstance(inst_instance.origin.value, Add):
            base, index = inst_instance.origin.operand_instances
            if isinstance(index.origin.value, Datasize) or (
                isinstance(index.origin.value, ConstantInt)
                and (index.origin.value.value % 32 == 0 or index.origin.value.value == 4)
            ):
                return self._find_encode_ptr(base.origin)
            else:
                return None
        elif (
            isinstance(inst_instance.origin.value, YulFuncInst)
            and inst_instance.origin.value.name == "allocate_unbounded"
        ):
            return inst_instance.origin
        else:
            return None

    def _record_call_args(self, inst_instance: ValueInstance):
        call_args = []
        type_str_with_tail = inst_instance.value.type_str
        if type_str_with_tail == "_to__fromStack":
            type_tuple_list = []
        else:
            type_tuple_list, tail_str = TypeParser.parse_multi_type_str(type_str_with_tail)
        stringliteral_number = 0
        two_args_calldata_ptr_number = 0
        for type_index, type_tuple in enumerate(type_tuple_list):
            type_str = TypeParser.parse_result_to_str(type_tuple)
            if "stringliteral" in type_str:
                stringliteral_number += 1
                arg_instance = inst_instance
            elif "calldata_ptr" in type_str:
                arg_instance = inst_instance.operand_instances[
                    type_index + 1 - stringliteral_number + two_args_calldata_ptr_number
                ]
                if is_two_args_calldata_ptr(type_str):
                    two_args_calldata_ptr_number += 1
            else:
                arg_instance = inst_instance.operand_instances[
                    type_index + 1 - stringliteral_number + two_args_calldata_ptr_number
                ]
            call_args.append(arg_instance)
        return call_args

    def _record_call_signature(self, inst_instance: ValueInstance):
        if not (len(self.info.path) > 0 and len(self.info.path[-1].inst_instances) > 1):
            return None
        pre_vi = self.info.path[-1].inst_instances[-2]

        if (
            isinstance(pre_vi.value, Mstore)
            and (len(pre_vi.operand_instances[1].operand_instances) == 1)
            and isinstance(pre_vi.operand_instances[1].operand_instances[0].value, ConstantInt)
        ):
            function_signature = pre_vi.operand_instances[1].operand_instances[0].value.value
            return function_signature
        elif isinstance(pre_vi.value, Mstore) and isinstance(pre_vi.operand_instances[1].value, ConstantInt):
            function_signature = pre_vi.operand_instances[1].value.value
            function_signature = function_signature >> 224
            return function_signature
        elif (
            isinstance(pre_vi.value, Mstore)
            and isinstance(pre_vi.operand_instances[1].value, TypeConvertInstruction)
            and isinstance(pre_vi.operand_instances[1].origin.value, ConstantInt)
        ):
            function_signature = pre_vi.operand_instances[1].origin.value.value
            return function_signature >> 224

        elif (
            isinstance(pre_vi.value, Mstore)
            and isinstance(pre_vi.operand_instances[1].value, ExtractReturnValue)
            and isinstance(pre_vi.operand_instances[1].origin.value, ConstantInt)
        ):
            function_signature = pre_vi.operand_instances[1].origin.value.value
            return function_signature >> 224
        else:
            return None

    def is_mutual_exclusive(self, constraint1: Constraint, constraint2: Constraint):
        if constraint1.condition_key != constraint2.condition_key:
            return False
        if constraint1.is_eq != constraint2.is_eq:
            return constraint1.case_value == constraint2.case_value
        elif constraint1.is_eq and constraint2.is_eq:
            return constraint1.case_value != constraint2.case_value
        else:
            return False

    def is_violate_constraints(self, constraints: List[Constraint]):
        if len(constraints) == 1:
            _constraint = constraints[0]
            if isinstance(_constraint.condition.value, Gt):
                operand0, operand1 = _constraint.condition.operand_instances
                if isinstance(operand0.value, ConstantInt) and isinstance(operand1.value, Returndatasize):
                    assert _constraint.is_eq
                    assert _constraint.case_value in (0, 1)
                    return _constraint.case_value == 1

        for constraint in constraints:
            if constraint.solve_result is True:
                continue
            elif constraint.solve_result is False:
                return True
            for i in self.info.fork_index_list:
                if i + 1 >= len(self.info.path):
                    break
                path_constraints = self.info.path[i + 1]._last_fork_constraints
                for path_constraint in path_constraints:
                    if self.is_mutual_exclusive(path_constraint, constraint):
                        return True
        return False
