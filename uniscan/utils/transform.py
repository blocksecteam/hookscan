import re
from collections import defaultdict
from typing import TYPE_CHECKING, Sequence

from uniscan.components.basic_block import BasicBlock
from uniscan.components.constant import ConstantInt
from uniscan.components.evm_instructions import Revert
from uniscan.components.function import FunctionType
from uniscan.components.instruction import (
    BranchInst,
    CallInst,
    ExtractReturnValue,
    Instruction,
    MathInst,
    UnreachableInst,
    YulFuncInst,
)
from uniscan.components.memory_instructions import memory_function_to_insts_and_returns
from uniscan.components.storage_instructions import storage_function_to_insts_and_returns
from uniscan.components.type_convert_instruction import TypeConvertInstruction
from uniscan.components.value import Value

if TYPE_CHECKING:
    from uniscan.components.contract import Contract


def remove_instruction_from_basic_block(inst: Instruction, update_cfg=True):
    assert isinstance(inst, Instruction)
    bb = inst.basic_block
    assert bb.instructions[inst.bb_index] == inst
    for i in range(inst.bb_index, len(bb.instructions) - 1):
        bb.instructions[i] = bb.instructions[i + 1]
        bb.instructions[i].bb_index = i
    bb.instructions.pop()
    inst.basic_block = None  # pyright: ignore

    # NOTE manually add terminator later
    if inst.is_terminator_type:
        bb.terminator = None
        if update_cfg:
            for succ in bb.successors:
                succ.predecessors.remove(bb)
            bb.successors.clear()


def insert_instructions_into_basic_block(bb: BasicBlock, index: int, insts: Sequence[Instruction]):
    # NOTE not support modifying terminator
    assert all(not _inst.is_terminator_type for _inst in insts)
    assert index < len(bb.instructions)
    if len(insts) == 0:
        return
    for i in range(len(insts)):
        insts[i].basic_block = bb
        insts[i].bb_index = index + i
    head, tail = bb.instructions[:index], bb.instructions[index:]
    for tail_inst in tail:
        tail_inst.bb_index += len(insts)
    bb.instructions = head + list(insts) + tail


def replace_instruction_in_place(from_inst: Instruction, to_inst: Instruction):
    # NOTE not support modifying terminator
    assert not from_inst.is_terminator_type
    bb = from_inst.basic_block
    bb_index = from_inst.bb_index
    bb.instructions[bb_index] = to_inst
    to_inst.basic_block = bb
    to_inst.bb_index = bb_index
    from_inst.basic_block = None  # pyright: ignore


def replace_terminator_to_unreachable(inst: Instruction, unuse_all_operands=True):
    bb = inst.basic_block
    remove_instruction_from_basic_block(inst)
    if unuse_all_operands:
        inst.unuse_all_operands()
    UnreachableInst(bb)


def replace_call_inst_to_values(inst: CallInst, values: Sequence[Value], remove_from_bb):
    if remove_from_bb:
        remove_instruction_from_basic_block(inst)
    inst.unuse_all_operands()

    for extract in inst.users:
        assert isinstance(extract, ExtractReturnValue)
        remove_instruction_from_basic_block(extract)

        for u in extract.users:
            for i, v in enumerate(u.operands):
                if v == extract:
                    u.replace_operand(i, values[extract.return_index])


def replace_storage_function(inst: CallInst) -> bool:
    insts, indexes = storage_function_to_insts_and_returns(inst)
    assert (insts is None) == (indexes is None)
    if insts is None:
        return False

    values = [insts[i] for i in indexes]  # pyright: ignore
    bb = inst.basic_block
    old_index = inst.bb_index
    replace_call_inst_to_values(inst, values, remove_from_bb=True)
    insert_instructions_into_basic_block(bb, old_index, insts)
    return True


def special_transform_in_memory(inst: CallInst) -> bool:
    if (
        inst.called_function.name.startswith("abi_decode_tuple")
        or inst.called_function.name.startswith("calldata_array_index_access")
        or inst.called_function.name.startswith("access_calldata_tail")
    ):
        return_count = inst.called_function.return_count
        assert inst.called_function.has_return

        if inst.called_function.name.startswith("abi_decode_tuple"):
            YulFuncInst_name = inst.called_function.name
        elif inst.called_function.name.startswith(
            "calldata_array_index_access"
        ) or inst.called_function.name.startswith("access_calldata_tail"):
            YulFuncInst_name = inst.called_function.name

        new_insts = [
            YulFuncInst(
                basic_block=None,
                name=YulFuncInst_name,  # pyright: ignore
                args=inst.arguments,
                return_index=i,
                return_count=return_count,
                allow_none_bb=True,
                yul_source_map=inst.yul_source_map,
                id_group=inst.id_group,
            )
            for i in range(return_count)
        ]
        insts = []
        for new_inst in new_insts:
            tmp_insts, tmp_indexes = memory_function_to_insts_and_returns(new_inst)
            assert (tmp_insts is None) == (tmp_indexes is None)
            if tmp_insts is None:
                return False
            insts += tmp_insts
        bb = inst.basic_block
        bb_index = inst.bb_index

        replace_call_inst_to_values(inst, insts, remove_from_bb=True)
        insert_instructions_into_basic_block(bb, bb_index, insts)

        return True
    else:
        return False


def replace_memory_function(inst: CallInst) -> bool:
    if inst.called_function.name == "revert_forward_1" or inst.called_function.name.startswith("panic_error_0x"):
        inst_succ = inst.basic_block.instructions[inst.bb_index + 1]
        bb = inst.basic_block
        yul_source_map = inst.yul_source_map
        assert isinstance(inst_succ, BranchInst)
        args = [ConstantInt(inst.id_group, 0), ConstantInt(inst.id_group, 0)]
        tmp_revert = Revert(
            args=args, basic_block=None, yul_source_map=yul_source_map, allow_none_bb=True, id_group=inst.id_group
        )
        replace_instruction_in_place(inst, tmp_revert)
        replace_terminator_to_unreachable(inst_succ)
        return True

    if inst.called_function.name == "abi_decode_tuple_" or inst.called_function.name == "abi_decode_tuple__fromMemory":
        remove_instruction_from_basic_block(inst)
        inst.unuse_all_operands()
        return True

    # abi_decode_tuple case has many return values, needs conversion to multiple instructions
    if special_transform_in_memory(inst):
        return True

    # normal memory replace
    else:
        insts, indexes = memory_function_to_insts_and_returns(inst)
        assert (insts is None) == (indexes is None)
        if insts is None:
            return False

        values = [insts[i] for i in indexes]  # pyright: ignore
        bb = inst.basic_block
        old_index = inst.bb_index
        replace_call_inst_to_values(inst, values, remove_from_bb=True)
        insert_instructions_into_basic_block(bb, old_index, insts)
        return True


def location(type_str: str):
    type_str = type_str.rstrip("_ptr")
    if type_str.endswith("calldata"):
        return "calldata"
    elif type_str.endswith("memory"):
        return "memory"
    elif type_str.endswith("storage"):
        return "storage"
    else:
        return None


def repalce_special_type_convert_function(inst: CallInst) -> bool:
    # NOTE convert_array_t_string_calldata_ptr_to_t_bytes_calldata_ptr has 2 return values: offset/length
    func = inst.called_function
    bb = inst.basic_block
    bb_index = inst.bb_index
    if func.name == "convert_array_t_string_calldata_ptr_to_t_bytes_calldata_ptr":
        from_type_str = "t_string_calldata_ptr"
        to_type_str = "t_bytes_calldata_ptr"
    elif func.name == "convert_array_t_bytes_calldata_ptr_to_t_string_calldata_ptr":
        from_type_str = "t_bytes_calldata_ptr"
        to_type_str = "t_string_calldata_ptr"
    else:
        return False
    tc_inst_offset = TypeConvertInstruction(
        basic_block=None,
        allow_none_bb=True,
        from_type_str=from_type_str,
        to_type_str=to_type_str,
        args=[inst.arguments[0]],
        yul_source_map=inst.yul_source_map,
        id_group=inst.id_group,
    )

    tc_inst_length = TypeConvertInstruction(
        basic_block=None,
        allow_none_bb=True,
        from_type_str=from_type_str,
        to_type_str=to_type_str,
        args=[inst.arguments[1]],
        yul_source_map=inst.yul_source_map,
        id_group=inst.id_group,
    )
    new_insts = [tc_inst_offset, tc_inst_length]
    replace_call_inst_to_values(inst, new_insts, remove_from_bb=True)
    insert_instructions_into_basic_block(bb, bb_index, new_insts)
    return True


def replace_type_convert_function(inst: CallInst) -> bool:
    if repalce_special_type_convert_function(inst):
        return True
    func = inst.called_function
    if not func.name.startswith("convert"):
        return False
    if len(func.arguments) != 1:
        return False
    if func.return_count != 1:
        return False
    m = re.match(r"convert(?:_array)?_(.*)_to_(.*)", func.name)
    assert m
    from_type_str, to_type_str = m.groups()
    if location(from_type_str) != location(to_type_str):
        return False
    tc_inst = TypeConvertInstruction(
        basic_block=None,
        allow_none_bb=True,
        from_type_str=from_type_str,
        to_type_str=to_type_str,
        args=inst.arguments,
        yul_source_map=inst.yul_source_map,
        id_group=inst.id_group,
    )
    replace_instruction_in_place(inst, tc_inst)
    replace_call_inst_to_values(inst, [tc_inst], remove_from_bb=False)
    return True


def replace_math_function(inst: CallInst):
    return_count = inst.called_function.return_count
    if inst.called_function.name.startswith(
        ("increment", "decrement", "wrapping", "checked", "mod")
    ) and inst.called_function.name not in ("checked_exp_unsigned", "checked_exp_helper"):
        new_inst = MathInst(
            basic_block=None,
            name=inst.called_function.name,
            args=inst.arguments,
            return_index=0 if return_count != 0 else None,
            return_count=return_count,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            id_group=inst.id_group,
        )
        replace_instruction_in_place(inst, new_inst)
        replace_call_inst_to_values(inst, [new_inst], remove_from_bb=False)
        return True
    else:
        return False


def replace_builtin_non_multi_return_function(inst: CallInst):
    return_count = inst.called_function.return_count
    if return_count >= 2:
        return False
    if inst.called_function.name.startswith("require_helper"):
        return False
    if inst.called_function.name.startswith("dispatch_internal"):
        return False
    if inst.called_function.name.startswith("constant"):
        return False
    if inst.called_function.name.startswith("assert_helper"):
        return False

    # NOTE should be only revert_error.*
    if not inst.called_function.has_return:
        return False

    new_inst = YulFuncInst(
        basic_block=None,
        name=inst.called_function.name,
        args=inst.arguments,
        return_index=0 if return_count != 0 else None,
        return_count=return_count,
        allow_none_bb=True,
        yul_source_map=inst.yul_source_map,
        id_group=inst.id_group,
    )
    replace_instruction_in_place(inst, new_inst)
    replace_call_inst_to_values(inst, [new_inst], remove_from_bb=False)

    if new_inst.basic_block.instructions[-1] == new_inst:
        assert new_inst.name.startswith("revert_error")
        assert new_inst.basic_block.function.type == FunctionType.RUNTIME
        UnreachableInst(new_inst.basic_block, yul_source_map=inst.yul_source_map)

    return True


def replace_builtin_multi_return_function(inst: CallInst):
    return_count = inst.called_function.return_count
    if return_count < 2:
        return False

    assert inst.called_function.has_return
    new_insts = [
        YulFuncInst(
            basic_block=None,
            name=inst.called_function.name,
            args=inst.arguments,
            return_index=i,
            return_count=return_count,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            id_group=inst.id_group,
        )
        for i in range(return_count)
    ]
    bb = inst.basic_block
    bb_index = inst.bb_index
    replace_call_inst_to_values(inst, new_insts, remove_from_bb=True)
    insert_instructions_into_basic_block(bb, bb_index, new_insts)

    assert bb.instructions[-1] != new_insts[-1]
    return True


def replace_builtin_function(inst: CallInst) -> bool:
    if replace_type_convert_function(inst):
        return True

    if replace_storage_function(inst):
        return True

    if replace_memory_function(inst):
        return True

    if replace_math_function(inst):
        return True

    if replace_builtin_non_multi_return_function(inst):
        return True

    if replace_builtin_multi_return_function(inst):
        return True

    return False


def replace_builtin_functions(contract: "Contract"):
    to_del_name = defaultdict(set)

    for func in contract.all_functions:
        if func.name in to_del_name[func.is_runtime]:
            continue
        for bb in func.basic_blocks:
            for inst in bb.instructions.copy():
                # NOTE removed
                if inst.basic_block is None:
                    continue
                if not isinstance(inst, CallInst):
                    continue
                called_func = inst.called_function
                if called_func.type != FunctionType.YUL_FUNCTION and called_func.type != FunctionType.CONSTANT:
                    continue
                assert func.is_runtime == called_func.is_runtime
                if replace_builtin_function(inst):
                    to_del_name[func.is_runtime].add(called_func.name)

    for is_runtime, set_ in to_del_name.items():
        if is_runtime:
            functions_dict = contract.runtime_functions_dict
        else:
            functions_dict = contract.creation_functions_dict
        for name in set_:
            del functions_dict[name]

    contract._refresh_all_functions()
