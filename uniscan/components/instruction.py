from typing import TYPE_CHECKING, Dict, List, Optional, Sequence, Tuple, Union

from uniscan.components.constant import Constant, User
from uniscan.components.unique_id import IdGroup
from uniscan.components.value import Value
from uniscan.utils.two_args_calldataptr import is_two_args_calldata_ptr
from uniscan.utils.type_parser import TypeParser

if TYPE_CHECKING:
    from uniscan.components.basic_block import BasicBlock
    from uniscan.components.function import Function


class Instruction(User):
    def __init__(
        self,
        basic_block: Optional["BasicBlock"],
        allow_none_bb: Optional[bool] = False,
        yul_source_map: Optional[Tuple] = None,
        id_group: Optional[IdGroup] = None,
    ) -> None:
        if id_group is None:
            assert basic_block is not None
            id_group = basic_block.id_group
        super().__init__(id_group)

        self.yul_source_map = yul_source_map

        if basic_block is None:
            assert allow_none_bb, "basic_block of instruction is None"
            return
        self.basic_block = basic_block
        assert basic_block.terminator is None
        self.bb_index = len(basic_block.instructions)
        basic_block.instructions.append(self)
        if self.is_terminator_type:
            basic_block.terminator = self

    def info(self):
        raise NotImplementedError

    @property
    def contract(self):
        return self.basic_block.function.contract

    @property
    def is_terminator_type(self):
        return isinstance(
            self,
            (
                ReturnInst,
                BranchInst,
                SwitchInst,
                UnreachableInst,
            ),
        )

    def __repr__(self):
        return self.info()

    def info_rvalue(self):
        return f"%{self.id}"


class ReturnInst(Instruction):
    def __init__(self, values: List[Value], basic_block: "BasicBlock", yul_source_map: Optional[Tuple] = None) -> None:
        super().__init__(basic_block, yul_source_map=yul_source_map)
        self.use_all(values)

    @property
    def values(self):
        return self.operands

    def info(self):
        values = ", ".join(f"{x.info_rvalue()}" for x in self.values)
        return f"function_return ({values})"


class CallInst(Instruction):
    def __init__(
        self,
        function: "Function",
        args: List[Value],
        basic_block: "BasicBlock",
        yul_source_map: Optional[Tuple] = None,
    ) -> None:
        super().__init__(basic_block, yul_source_map=yul_source_map)
        self.use_all(args)
        self.use(function)

    @property
    def called_function(self) -> "Function":
        return self.operands[-1]

    @property
    def arguments(self):
        return self.operands[:-1]

    def info(self):
        args = ", ".join(
            (x.info_rvalue() if hasattr(x, "info_rvalue") else "?") for x in self.arguments  # pyright: ignore
        )
        return f"%{self.id} = call {self.called_function.name}({args})"


class ExtractReturnValue(Instruction):
    def __init__(
        self,
        call_inst: CallInst,
        return_index: int,
        return_count: int,
        basic_block: "BasicBlock",
        yul_source_map: Optional[Tuple] = None,
    ) -> None:
        super().__init__(basic_block, yul_source_map=yul_source_map)
        self.use(call_inst)
        self.return_index = return_index
        self.return_count = return_count

    @property
    def call_instruction(self) -> CallInst:
        return self.operands[0]

    def info(self):
        return f"%{self.id} = extract {self.return_index}-th value" + f" from {self.call_instruction.info_rvalue()}"


class PHINode(Instruction):
    def __init__(
        self,
        predecessors: List["BasicBlock"],
        values: List[Value],
        basic_block: "BasicBlock",
        yul_source_map: Optional[Tuple] = None,
    ) -> None:
        assert all(v is not None for v in values)
        super().__init__(basic_block, yul_source_map=yul_source_map)
        assert len(predecessors) == len(values)
        self.use_all(values)
        self.predecessors = list(predecessors)

    @property
    def values(self):
        return self.operands

    def add_predecessor(self, predecessor, value):
        self.predecessors.append(predecessor)
        self.use(value)

    def get_value_from_predecessor(self, predecessor):
        index = self.predecessors.index(predecessor)
        return self.values[index]

    def info(self):
        args = ", ".join(f"%{bb.id}: {v.info_rvalue()}" for bb, v in zip(self.predecessors, self.values))
        return f"%{self.id} = phi({args})"


class BranchInst(Instruction):
    # NOTE successors: [succ] or [true_succ, false_succ]
    # NOTE operands: [succ] or [condition, true_succ, false_succ]
    def __init__(
        self,
        condition: Optional[Value],
        successors: List["BasicBlock"],
        basic_block: "BasicBlock",
        yul_type=None,
        yul_source_map: Optional[Tuple] = None,
    ) -> None:
        assert len(basic_block.successors) == 0

        super().__init__(basic_block, yul_source_map=yul_source_map)
        if condition is None:
            assert len(successors) == 1
        else:
            assert len(successors) == 2
            self.use(condition)
        self.use_all(successors)

        self.yul_type = yul_type

        basic_block.successors.extend(successors)
        for succ in successors:
            succ.predecessors.append(basic_block)

    @property
    def condition(self):
        assert self.is_conditional
        return self.operands[0]

    @property
    def is_conditional(self):
        return len(self.operands) == 3

    def get_successor(self, when: Optional[bool] = None) -> "BasicBlock":
        if not self.is_conditional:
            assert when is None
            return self.operands[0]

        assert isinstance(when, bool)
        return self.operands[2 - int(when)]

    @property
    def true_successor(self):
        return self.get_successor(True)

    @property
    def false_successor(self):
        return self.get_successor(False)

    def info(self):
        if self.is_conditional:
            return (
                "br"
                + f" %{self.get_successor(True).id}"
                + f" if {self.condition.info_rvalue()}"
                + f" else %{self.get_successor(False).id}"
            )
        else:
            return f"br %{self.get_successor(None).id}"


class SwitchInst(Instruction):
    def __init__(
        self,
        condition: Value,
        default_bb: Optional["BasicBlock"],
        case_succs: List[Union[Optional[Constant], "BasicBlock"]],
        basic_block: "BasicBlock",
        yul_source_map: Optional[Tuple] = None,
    ) -> None:
        assert len(basic_block.successors) == 0

        super().__init__(basic_block, yul_source_map=yul_source_map)
        self.use(condition)
        self.use(default_bb)
        self.use_all(case_succs)
        self._case_to_successor = None

        basic_block.successors.append(self.default_successor)
        basic_block.successors.extend(self.case_to_successor.values())
        for succ in basic_block.successors:
            succ.predecessors.append(basic_block)

    @property
    def condition(self):
        return self.operands[0]

    @property
    def default_successor(self):
        return self.operands[1]

    @property
    def case_to_successor(self) -> Dict[Constant, "BasicBlock"]:
        if self._case_to_successor is None:
            self._case_to_successor = {self.operands[i]: self.operands[i + 1] for i in range(2, len(self.operands), 2)}
        return self._case_to_successor

    def info(self):
        cases = ", ".join(f"{case.info_rvalue()}: %{bb.id}" for case, bb in self.case_to_successor.items())
        return f"switch {self.condition.info_rvalue()}" + f" default: %{self.default_successor.id} {{ {cases} }}"


class AbstractEVMInst(Instruction):
    def __init__(
        self,
        args: Sequence[Value],
        basic_block: Optional["BasicBlock"],
        allow_none_bb: bool = False,
        yul_source_map: Optional[Tuple] = None,
        id_group: Optional[IdGroup] = None,
    ) -> None:
        assert type(self) != AbstractEVMInst, "can only be created through subclasses"
        super().__init__(basic_block, yul_source_map=yul_source_map, allow_none_bb=allow_none_bb, id_group=id_group)
        self.use_all(args)

    @property
    def arguments(self):
        return self.operands

    def info(self):
        args = ", ".join(
            (x.info_rvalue() if hasattr(x, "info_rvalue") else "?") for x in self.arguments  # pyright: ignore
        )
        return f"%{self.id} = evm_{self.name}({args})"


class AbstractYulInst(Instruction):
    def __init__(
        self,
        args: List[Value],
        basic_block: "BasicBlock",
        yul_source_map: Optional[Tuple] = None,
    ) -> None:
        assert type(self) != AbstractYulInst, "can only be created through subclasses"
        super().__init__(basic_block, yul_source_map=yul_source_map)
        self.use_all(args)

    @property
    def arguments(self):
        return self.operands

    def info(self):
        args = ", ".join(
            (x.info_rvalue() if hasattr(x, "info_rvalue") else "?") for x in self.arguments  # pyright: ignore
        )
        return f"%{self.id} = yul_{self.name}({args})"


class UnreachableInst(Instruction):
    def info(self):
        return "Unreachable"


class MathInst(Instruction):
    def __init__(
        self,
        basic_block: Optional["BasicBlock"],
        name: str,
        args: List[Value],
        return_index: Optional[int],
        return_count: int,
        allow_none_bb=False,
        yul_source_map: Optional[Tuple] = None,
        id_group: Optional[IdGroup] = None,
    ) -> None:
        super().__init__(basic_block, allow_none_bb, yul_source_map=yul_source_map, id_group=id_group)
        self.name = name
        self.use_all(args)
        assert return_count == 1 and return_index == 0 or name == "checked_exp_helper"
        assert len(name.split("_t_")) == 2 or (
            len(name.split("_t_")) == 3 and self.name.startswith(("checked_exp", "wrapping_exp"))
        )
        self.type_str = "t_" + name.split("_t_")[1] if not self.name.startswith("exp") else None
        self.base_type_str = "t_" + name.split("_t_")[1] if self.name.startswith("exp") else None
        self.exp_type_str = "t_" + name.split("_t_")[2] if self.name.startswith("exp") else None
        if "wrapping" in self.name:
            self.checked = False
        else:
            self.checked = True
        if self.name.startswith("increment"):
            self.operation = "increment"
        elif self.name.startswith("decrement"):
            self.operation = "decrement"
        elif self.name.startswith("mod"):
            self.operation = "mod"
        else:
            self.operation = self.name.split("_")[1]
        assert self.operation in (
            "sub",
            "add",
            "div",
            "mul",
            "exp",
            "mod",
            "increment",
            "decrement",
        )

    @property
    def arguments(self) -> List[Value]:
        return self.operands

    def info(self):
        args = ", ".join(
            (x.info_rvalue() if hasattr(x, "info_rvalue") else "?") for x in self.arguments  # pyright: ignore
        )
        return f"%{self.id} = {self.name}({args})"


class YulFuncInst(Instruction):
    def __init__(
        self,
        basic_block: Optional["BasicBlock"],
        name: str,
        args: List[Value],
        return_index: Optional[int],
        return_count: int,
        allow_none_bb=False,
        yul_source_map: Optional[Tuple] = None,
        id_group: Optional[IdGroup] = None,
    ) -> None:
        super().__init__(basic_block, allow_none_bb, yul_source_map=yul_source_map, id_group=id_group)
        self.name = name
        self.use_all(args)
        assert (return_count == 0 and return_index is None) or return_count > return_index  # pyright: ignore
        self.return_count = return_count
        self.return_index = return_index
        calldata_ptr_offset = False
        calldata_ptr_length = False
        calldata_ptr_count = 0
        if name.startswith("abi_decode_tuple"):
            type_str_with_tail = name[17:]
            type_tuple_list, tail_str = TypeParser.parse_multi_type_str(type_str_with_tail)
            now_return_index = 0
            has_two_args = 0
            i = 0
            while i < len(type_tuple_list):
                type_str = TypeParser.parse_result_to_str(type_tuple_list[i])
                if is_two_args_calldata_ptr(type_str) and has_two_args:  # length arg
                    calldata_ptr_offset = False
                    calldata_ptr_length = True
                    calldata_ptr_count += 1
                    has_two_args = 0
                    i += 1
                elif is_two_args_calldata_ptr(type_str) and not has_two_args:  # offset arg
                    calldata_ptr_offset = True
                    calldata_ptr_length = False
                    has_two_args = 1
                elif not is_two_args_calldata_ptr(type_str):
                    calldata_ptr_offset = False
                    calldata_ptr_length = False
                    i += 1
                now_return_index += 1
                if now_return_index > return_index:  # pyright: ignore
                    break

        self.calldata_ptr_offset = calldata_ptr_offset
        self.calldata_ptr_length = calldata_ptr_length
        self.calldata_ptr_count = calldata_ptr_count

    @property
    def arguments(self) -> List[Value]:
        return self.operands

    def info(self):
        args = ", ".join(
            (x.info_rvalue() if hasattr(x, "info_rvalue") else "?") for x in self.arguments  # pyright: ignore
        )
        if self.return_count == 0:
            return f"{self.name}({args})"
        elif self.return_count == 1:
            return f"%{self.id} = {self.name}({args})"
        else:
            return f"%{self.id} = {self.name}({args}) {self.return_index}-th ret"
