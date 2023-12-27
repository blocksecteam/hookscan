import re
from typing import List, Optional, Tuple

from uniscan.components.basic_block import BasicBlock
from uniscan.components.instruction import CallInst, Instruction
from uniscan.components.unique_id import IdGroup
from uniscan.utils.two_args_calldataptr import is_two_args_calldata_ptr


class AbstractStorageInst(Instruction):
    def __init__(
        self,
        basic_block: Optional["BasicBlock"],
        inst_args: list,
        base_str: str,
        type_str: str,
        pos_args: list,
        value_args: list,
        allow_none_bb=False,
        yul_source_map=None,
        id_group: Optional[IdGroup] = None,
    ) -> None:
        super().__init__(basic_block, allow_none_bb, yul_source_map, id_group)
        self.inst_args = inst_args
        self.use_all(inst_args)
        self.base_str = base_str
        self.type_str = type_str
        self.pos_args = pos_args
        self.value_args = value_args

    def info(self):
        return str(type(self))

    def __jrepr__(self):
        return self.__class__.__name__


class StorageArrayLength(AbstractStorageInst):
    def __init__(
        self,
        basic_block: Optional["BasicBlock"],
        inst_args: list,
        base_str: str,
        type_str: str,
        pos_args: list,
        value_args: list,
        allow_none_bb=False,
        yul_source_map=None,
        id_group: Optional[IdGroup] = None,
    ) -> None:
        super().__init__(
            basic_block,
            inst_args,
            base_str,
            type_str,
            pos_args,
            value_args,
            allow_none_bb,
            yul_source_map,
            id_group=id_group,
        )


class StorageIndexInst(AbstractStorageInst):
    def __init__(
        self,
        basic_block: Optional["BasicBlock"],
        inst_args: list,
        base_str: str,
        type_str: str,
        pos_args: list,
        value_args: list,
        allow_none_bb=False,
        yul_source_map=None,
        id_group: Optional[IdGroup] = None,
    ) -> None:
        super().__init__(
            basic_block,
            inst_args,
            base_str,
            type_str,
            pos_args,
            value_args,
            allow_none_bb,
            yul_source_map,
            id_group=id_group,
        )


class StorageOffsetInst(StorageIndexInst):
    def __init__(
        self,
        basic_block: Optional["BasicBlock"],
        inst_args: list,
        base_str: str,
        type_str: str,
        pos_args: list,
        value_args: list,
        allow_none_bb=False,
        yul_source_map=None,
        id_group: Optional[IdGroup] = None,
    ) -> None:
        super().__init__(
            basic_block,
            inst_args,
            base_str,
            type_str,
            pos_args,
            value_args,
            allow_none_bb,
            yul_source_map,
            id_group=id_group,
        )


class StorageArrayIndexInst(StorageIndexInst):
    def __init__(
        self,
        basic_block: Optional["BasicBlock"],
        inst_args: list,
        base_str: str,
        type_str: str,
        pos_args: list,
        value_args: list,
        allow_none_bb=False,
        yul_source_map=None,
        id_group: Optional[IdGroup] = None,
    ) -> None:
        super().__init__(
            basic_block,
            inst_args,
            base_str,
            type_str,
            pos_args,
            value_args,
            allow_none_bb,
            yul_source_map,
            id_group=id_group,
        )


class StorageMappingIndexInst(StorageIndexInst):
    def __init__(
        self,
        basic_block: Optional["BasicBlock"],
        inst_args: list,
        base_str: str,
        type_str: str,
        pos_args: list,
        value_args: list,
        allow_none_bb=False,
        yul_source_map=None,
        id_group: Optional[IdGroup] = None,
    ) -> None:
        super().__init__(
            basic_block,
            inst_args,
            base_str,
            type_str,
            pos_args,
            value_args,
            allow_none_bb,
            yul_source_map,
            id_group=id_group,
        )


class StorageIOInst(AbstractStorageInst):
    def __init__(
        self,
        basic_block: Optional["BasicBlock"],
        inst_args: list,
        base_str: str,
        type_str: str,
        pos_args: list,
        value_args: list,
        allow_none_bb=False,
        yul_source_map=None,
        id_group: Optional[IdGroup] = None,
    ) -> None:
        super().__init__(
            basic_block,
            inst_args,
            base_str,
            type_str,
            pos_args,
            value_args,
            allow_none_bb,
            yul_source_map,
            id_group=id_group,
        )


class StorageUpdateInst(StorageIOInst):
    def __init__(
        self,
        basic_block: Optional["BasicBlock"],
        inst_args: list,
        base_str: str,
        type_str: str,
        pos_args: list,
        value_args: list,
        allow_none_bb=False,
        yul_source_map=None,
        action="common",
        id_group: Optional[IdGroup] = None,
    ) -> None:
        super().__init__(
            basic_block,
            inst_args,
            base_str,
            type_str,
            pos_args,
            value_args,
            allow_none_bb,
            yul_source_map,
            id_group=id_group,
        )
        self.action = action


class StorageReadInst(StorageIOInst):
    def __init__(
        self,
        basic_block: Optional["BasicBlock"],
        inst_args: list,
        base_str: str,
        type_str: str,
        pos_args: list,
        value_args: list,
        allow_none_bb=False,
        yul_source_map=None,
        action="common",
        id_group: Optional[IdGroup] = None,
    ) -> None:
        super().__init__(
            basic_block,
            inst_args,
            base_str,
            type_str,
            pos_args,
            value_args,
            allow_none_bb,
            yul_source_map,
            id_group=id_group,
        )


def default_assert_type_str_and_generate_pos_value_args(
    inst_args: list,
    pos_args_num: int,
    base_str: str,
    value_type_str: Optional[str],
    insert_offset: Optional[str] = None,
    pos_with_offset: bool = False,
):
    pos_args = inst_args[:pos_args_num]
    value_args = inst_args[pos_args_num:]

    if insert_offset is not None:
        pos_args += [insert_offset]

    if pos_with_offset:
        assert pos_args.__len__() == 2, "invalid pos_with_offset"
        pos_args[-1] = f"offset_{pos_args[-1]}"

    if value_type_str is None:  # Some instructions just don't have a value_type_str
        return pos_args, value_args

    if value_type_str.startswith(
        "t_stringliteral_"
    ):  # String literal, the operand is in the function name, and the value part of the parameter is empty
        assert value_args.__len__() == 0, f"unexpected {base_str} arguments: {inst_args}"
        value_args += [value_type_str[len("t_stringliteral_") :]]
    elif is_two_args_calldata_ptr(value_type_str):
        assert value_args.__len__() == 2, f"unexpected {base_str} arguments: {inst_args}"
    else:
        assert value_args.__len__() == 1, f"unexpected {base_str} arguments: {inst_args}"

    return pos_args, value_args


def storage_function_to_insts_and_returns(
    inst: CallInst,
) -> Tuple[Optional[List[Instruction]], Optional[List[int]]]:

    function_name = inst.called_function.name
    if function_name.startswith("update_storage_value_offset"):
        base_str = "update_storage_value_offset"
        offset = re.search(r"\d+", function_name[len(base_str) + 1 :]).group(0)  # pyright: ignore
        type_str = function_name[len(base_str) + 1 + len(offset) :]
        assert type_str.count("_to_") == 1, f"unexpected {base_str} type_str format: {type_str}"

        from_str: str = type_str.split("_to_")[0]

        pos_args, value_args = default_assert_type_str_and_generate_pos_value_args(
            inst.arguments, 1, base_str, from_str, insert_offset=offset, pos_with_offset=True
        )

        new_inst = StorageUpdateInst(
            None,
            inst.arguments,
            base_str,
            type_str,
            pos_args,
            value_args,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            action="common",
            id_group=inst.id_group,
        )

        return [new_inst], [0]

    elif function_name.startswith("update_storage_value"):
        base_str = "update_storage_value"
        type_str = function_name[len(base_str) + 1 :]
        assert type_str.count("_to_") == 1, f"unexpected {base_str} type_str format: {type_str}"

        from_str: str = type_str.split("_to_")[0]

        pos_args, value_args = default_assert_type_str_and_generate_pos_value_args(
            inst.arguments, 2, base_str, from_str, pos_with_offset=True
        )

        new_inst = StorageUpdateInst(
            None,
            inst.arguments,
            base_str,
            type_str,
            pos_args,
            value_args,
            allow_none_bb=True,
            action="common",
            id_group=inst.id_group,
        )

        return [new_inst], [0]

    elif function_name.startswith("storage_set_to_zero"):
        base_str = "storage_set_to_zero"
        type_str = function_name[len(base_str) + 1 :]
        assert inst.arguments.__len__() == 2, f"unexpected {base_str} arguments: {inst.arguments}"

        pos_args, value_args = default_assert_type_str_and_generate_pos_value_args(
            inst.arguments, 2, base_str, None, pos_with_offset=True
        )

        new_inst = StorageUpdateInst(
            None,
            inst.arguments,
            base_str,
            type_str,
            pos_args,
            value_args,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            action="clean_storage",
            id_group=inst.id_group,
        )

        return [new_inst], [0]

    elif function_name.startswith("array_push_from"):
        base_str = "array_push_from"
        type_str = function_name[len(base_str) + 1 :]
        assert type_str.count("_to_") == 1, f"unexpected {base_str} type_str format: {type_str}"

        from_str: str = type_str.split("_to_")[0]

        pos_args, value_args = default_assert_type_str_and_generate_pos_value_args(
            inst.arguments, 1, base_str, from_str
        )

        new_inst = StorageUpdateInst(
            None,
            inst.arguments,
            base_str,
            type_str,
            pos_args,
            value_args,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            action="array_push",
            id_group=inst.id_group,
        )

        return [new_inst], [0]

    elif function_name.startswith("array_push_zero"):
        base_str = "array_push_zero"
        type_str = function_name[len(base_str) + 1 :]
        assert inst.arguments.__len__() == 1, f"unexpected {base_str} arguments: {inst.arguments}"

        pos_args, value_args = default_assert_type_str_and_generate_pos_value_args(inst.arguments, 1, base_str, None)

        new_inst1 = StorageUpdateInst(
            None,
            inst.arguments,
            base_str,
            type_str,
            pos_args,
            value_args,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            action="array_push_zero",
            id_group=inst.id_group,
        )

        new_inst2 = StorageArrayIndexInst(
            None,
            inst.arguments,
            base_str,
            type_str,
            pos_args,
            value_args,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            id_group=inst.id_group,
        )

        new_inst3 = StorageOffsetInst(
            None,
            inst.arguments,
            base_str,
            type_str,
            pos_args,
            value_args,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            id_group=inst.id_group,
        )

        return [new_inst1, new_inst2, new_inst3], [1, 2]

    elif function_name.startswith("array_pop"):
        base_str = "array_pop"
        type_str = function_name[len(base_str) + 1 :]
        assert inst.arguments.__len__() == 1, f"unexpected {base_str} arguments: {inst.arguments}"

        pos_args, value_args = default_assert_type_str_and_generate_pos_value_args(inst.arguments, 1, base_str, None)

        new_inst = StorageUpdateInst(
            None,
            inst.arguments,
            base_str,
            type_str,
            pos_args,
            value_args,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            action="array_pop",
            id_group=inst.id_group,
        )

        return [new_inst], [0]

    elif function_name.startswith("read_from_storage_split_offset"):
        base_str = "read_from_storage_split_offset"
        offset = re.search(r"\d+", function_name[len(base_str) + 1 :]).group(0)  # pyright: ignore
        type_str = function_name[len(base_str) + 1 + len(offset) + 1 :]
        assert inst.arguments.__len__() == 1, f"unexpected {base_str} arguments: {inst.arguments}"

        pos_args, value_args = default_assert_type_str_and_generate_pos_value_args(
            inst.arguments, 1, base_str, None, insert_offset=offset, pos_with_offset=True
        )

        new_inst = StorageReadInst(
            None,
            inst.arguments,
            base_str,
            type_str,
            pos_args,
            value_args,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            id_group=inst.id_group,
        )

        return [new_inst], [0]

    elif function_name.startswith("read_from_storage_split_dynamic"):
        base_str = "read_from_storage_split_dynamic"
        type_str = function_name[len(base_str) + 1 :]
        assert inst.arguments.__len__() == 2, f"unexpected {base_str} arguments: {inst.arguments}"

        pos_args, value_args = default_assert_type_str_and_generate_pos_value_args(
            inst.arguments, 2, base_str, None, pos_with_offset=True
        )

        new_inst = StorageReadInst(
            None,
            inst.arguments,
            base_str,
            type_str,
            pos_args,
            value_args,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            id_group=inst.id_group,
        )

        return [new_inst], [0]

    elif function_name.startswith("storage_array_index_access"):
        base_str = "storage_array_index_access"
        type_str = function_name[len(base_str) + 1 :]
        assert inst.arguments.__len__() == 2, f"unexpected {base_str} arguments: {inst.arguments}"

        pos_args, value_args = default_assert_type_str_and_generate_pos_value_args(
            inst.arguments, 1, base_str, type_str
        )

        new_inst1 = StorageArrayIndexInst(
            None,
            inst.arguments,
            base_str,
            type_str,
            pos_args,
            value_args,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            id_group=inst.id_group,
        )

        new_inst2 = StorageOffsetInst(
            None,
            inst.arguments,
            base_str,
            type_str,
            pos_args,
            value_args,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            id_group=inst.id_group,
        )

        return [new_inst1, new_inst2], [0, 1]

    elif function_name.startswith("mapping_index_access"):
        base_str = "mapping_index_access"
        type_str = function_name[len(base_str) + 1 :]

        assert type_str.count("_of_") == 1, f"unexpected {base_str} type_str format: {type_str}"

        of_str: str = type_str.split("_of_")[1]

        pos_args, value_args = default_assert_type_str_and_generate_pos_value_args(inst.arguments, 1, base_str, of_str)

        new_inst = StorageMappingIndexInst(
            None,
            inst.arguments,
            base_str,
            type_str,
            pos_args,
            value_args,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            id_group=inst.id_group,
        )

        return [new_inst], [0]

    elif function_name.startswith("array_length") and (
        function_name.endswith("storage_ptr") or function_name.endswith("storage")
    ):
        base_str = "array_length"
        type_str = function_name[len("array_length") + 1 :]

        pos_args, value_args = default_assert_type_str_and_generate_pos_value_args(
            inst.arguments, 1, base_str, None, pos_with_offset=False
        )

        new_inst = StorageArrayLength(
            None,
            inst.arguments,
            base_str,
            type_str,
            pos_args,
            value_args,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            id_group=inst.id_group,
        )

        return [new_inst], [0]
    else:
        return None, None


all_storage_instructions = [
    StorageIOInst,
    StorageUpdateInst,
    StorageReadInst,
    StorageIndexInst,
    StorageArrayIndexInst,
    StorageOffsetInst,
    StorageMappingIndexInst,
    StorageArrayLength,
]

all_storage_instructions_dict = {
    storage_inst.__class__.__name__: storage_inst for storage_inst in all_storage_instructions
}
