from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple, Type, Union

from hookscan.components.basic_block import BasicBlock
from hookscan.components.constant import Constant
from hookscan.components.contract import Contract
from hookscan.components.function import Function, FunctionType
from hookscan.components.instruction import CallInst, Instruction, PHINode, ReturnInst
from hookscan.components.protect_handler import ProtectHandler
from hookscan.components.timeout_handler import TimeoutHandler
from hookscan.components.value import Argument, Value
from hookscan.core.instruction_instance import ValueInstance
from hookscan.detectors.base_detector import BaseDetector


@dataclass
class CallInfo:
    is_call: bool
    inst_instance: ValueInstance
    return_bb: Optional[BasicBlock] = None
    return_index: Optional[int] = None
    return_pre_bb: Optional[BasicBlock] = None
    return_loop_entry_pre_bb: Optional[bool] = None

    @property
    def inst(self) -> Union[CallInst, ReturnInst]:
        return self.inst_instance.value  # pyright: ignore

    @property
    def instances(self) -> List[ValueInstance]:
        return self.inst_instance.operand_instances

    def __repr__(self) -> str:
        if self.is_call:
            return f"call {self.inst.called_function.name}"  # pyright: ignore
        else:
            return f"return from {self.inst.basic_block.function.name}"


@dataclass
class PathNode:
    basic_block: BasicBlock
    start_index: int = 0
    current_index: Optional[int] = None
    call_info: Optional[CallInfo] = None
    _last_fork_constraints: Optional[List[Tuple[ValueInstance, bool, int]]] = None
    current_loop_entry_index: Optional[int] = None
    inst_instances: List[ValueInstance] = field(default_factory=list)

    detector_info_dict: Dict[Callable, List[Any]] = field(default_factory=lambda: defaultdict(list))

    condition_choose: Optional[Union[bool, int, str]] = None


@dataclass
class TraversalInfo:
    contract: Contract
    function: Function

    timeout_handler: TimeoutHandler
    all_res: Dict[Type["BaseDetector"], Any]
    is_end: bool  # NOTE only used for detector now
    only_run_not_protected: bool

    detector_relative_rounds: Dict["BaseDetector", int] = field(default_factory=lambda: defaultdict(int))
    has_done_function_list: List[str] = field(default_factory=list)
    protect_handler: ProtectHandler = field(default_factory=ProtectHandler)

    current_function_selector: Optional[Union[int, str]] = None
    entry_point_function: Optional[Function] = None

    path: List[PathNode] = field(default_factory=list)
    # NOTE len(successors) >= 2
    fork_index_list: List[int] = field(default_factory=list)
    protect_index_list: List[int] = field(default_factory=list)
    # NOTE yul function call, not evm call
    call_info_index_list: List[int] = field(default_factory=list)

    call_index_stack: List[int] = field(default_factory=list)

    loop_index_stack: List[int] = field(default_factory=list)

    # NOTE (path_node_index, inst_index)
    trigger_index_list: List[Tuple[int, int]] = field(default_factory=list)

    _path_node_stack: Dict[BasicBlock, Dict[int, List[PathNode]]] = field(
        default_factory=lambda: defaultdict(lambda: defaultdict(list))
    )

    _recursive_call_count_dict: Dict[Function, int] = field(default_factory=lambda: defaultdict(int))

    constant_instances: Dict[Value, ValueInstance] = field(default_factory=dict)

    def get_path_call_name_without_yul_function(self) -> List[str]:
        """Get current dfs path function name (source code only).

        returns:
            List[str]:
        """
        ret = []
        for i in self.call_info_index_list:
            call_return_inst = self.path[i].call_info.inst_instance.value  # pyright: ignore
            if isinstance(call_return_inst, CallInst):
                if call_return_inst.called_function.type in (FunctionType.EXTERNAL, FunctionType.INTERNAL):
                    ret.append(call_return_inst.called_function.name)
        return ret

    def get_path_call_name(self) -> List[str]:
        """Get current dfs path function name.

        returns:
            List[str]:
        """
        ret = []
        for i in self.call_info_index_list:
            call_return_inst = self.path[i].call_info.inst_instance.value  # pyright: ignore
            if isinstance(call_return_inst, CallInst):
                ret.append(call_return_inst.called_function.name)
        return ret

    def get_call_stack(self):
        """Get current dfs path CallInfo.

        returns:
            List[CallInfo]:

        """
        return [self.path[i].call_info for i in self.call_index_stack]

    def get_call_stack_functions(self) -> List[Function]:
        """Get current dfs path Function.

        returns:
            list[str]:

        """
        return [
            self.path[i].call_info.inst_instance.value.called_function for i in self.call_index_stack  # pyright: ignore
        ]

    def get_call_stack_names(self) -> List[str]:
        """Get current dfs call stack function name.

        returns:
            list[str]:

        """
        return [
            self.path[i].call_info.inst_instance.value.called_function.name  # pyright: ignore
            for i in self.call_index_stack
        ]

    def get_last_call_info_index(self, func: Optional[Function] = None):
        for index in reversed(self.call_index_stack):
            if func is None or self.path[index].call_info.inst.called_function == func:  # pyright: ignore
                return index
        else:
            raise Exception("last call not found")

    # NOTE get the last call info in call stack
    def get_last_call_info(self, func: Optional[Function] = None):
        """Get current dfs path latest CallInfo.

        returns:
            CallInfo: latest CallInfo

        """
        index = self.get_last_call_info_index(func)
        return self.path[index].call_info

    def _get_instance(
        self,
        v: Value,
        *,
        user_phi: Optional[PHINode] = None,
        path_node: Optional[PathNode] = None,
        info: Optional["TraversalInfo"] = None,
    ):
        if isinstance(v, Instruction):
            bb = v.basic_block
            index = v.bb_index
            start = max(i for i in self._path_node_stack[bb] if i <= index)

            if user_phi is not None and user_phi.basic_block == bb:
                path_node = self._path_node_stack[bb][start][-2]
            else:
                path_node = self._path_node_stack[bb][start][-1]
            return path_node.inst_instances[index - start]
        elif isinstance(v, Argument):
            call_info = self.get_last_call_info()
            assert call_info.is_call  # pyright: ignore
            return call_info.instances[v.index]  # pyright: ignore
        elif isinstance(v, Constant):
            if v not in self.constant_instances:
                instance = ValueInstance(v, path_node, info)
                self.constant_instances[v] = instance
                return instance
            else:
                return self.constant_instances[v]
        else:
            return None

    def is_tainted_by_calldata(self, value_instance: ValueInstance) -> bool:
        return "calldata" in value_instance.taints

    @property
    def is_in_loop(self) -> bool:
        return self.loop_index_stack.__len__() != 0

    def get_current_loop_entry_index(self) -> Optional[int]:
        if not self.is_in_loop:
            return None
        else:
            return self.loop_index_stack[-1]

    def get_current_loop_entry_path_node(self) -> Optional[PathNode]:
        if not self.is_in_loop:
            return None
        else:
            return self.path[self.loop_index_stack[-1]]

    @property
    def is_protected(self) -> bool:
        """Return whether current path is protected."""
        return len(self.protect_index_list) != 0

    @property
    def current_path_node(self):
        assert self.path
        return self.path[-1]

    @property
    def current_bb(self):
        return self.current_path_node.basic_block

    @property
    def current_inst(self) -> Instruction:
        return self.current_inst_instance.value  # pyright: ignore

    @property
    def current_inst_instance(self):
        path_node = self.current_path_node
        return path_node.inst_instances[-1]

    @property
    def current_inst_taints(self):
        return self.current_inst_instance.taints

    def get_path_instances(self, inst_type_list: Optional[Tuple[Type[Instruction], ...]] = None) -> List[ValueInstance]:
        """Return the path as 1-dimensional array.

        Args:
            inst_type_list (Optional[Tuple[Type[Instruction], ...]], optional): if not None,
            return list will only include specified instruction type, defaults to None.

        Returns:
            List[ValueInstance]: 1-dimensional array of ValueInstance
        """
        if inst_type_list is None:
            return [instance for instances in [(node.inst_instances) for node in self.path] for instance in instances]
        else:
            result = []
            for instance in [
                instance for instances in [(node.inst_instances) for node in self.path] for instance in instances
            ]:
                for inst_type in inst_type_list:
                    if isinstance(instance.value, inst_type):
                        result.append(instance)
                        break
            return result
