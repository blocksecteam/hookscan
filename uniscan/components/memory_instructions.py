import abc
from typing import List, Optional, Tuple, Union

from uniscan.components.basic_block import BasicBlock
from uniscan.components.instruction import CallInst, Instruction, YulFuncInst
from uniscan.components.unique_id import IdGroup
from uniscan.components.value import Value
from uniscan.utils.two_args_calldataptr import is_two_args_calldata_ptr
from uniscan.utils.type_parser import TypeParser


class AbstractMemoryInst(Instruction, metaclass=abc.ABCMeta):
    def __init__(
        self,
        basic_block: Optional[BasicBlock],
        args: List[Value],
        type_str: str,
        allow_none_bb=False,
        yul_source_map: Optional[Tuple] = None,
        id_group: Optional[IdGroup] = None,
    ) -> None:
        assert type(self) != AbstractMemoryInst, "can only be created through subclasses"
        Instruction.__init__(self, basic_block, allow_none_bb, yul_source_map, id_group)
        self.use_all(args)
        self.type_str = type_str

    def info(self):
        return str(type(self))


class AllocateMemory(AbstractMemoryInst):
    def __init__(
        self,
        basic_block: Optional[BasicBlock],
        args: List[Value],
        base_str: str,
        type_str: str,
        allow_none_bb=False,
        yul_source_map: Optional[Tuple] = None,
        id_group: Optional[IdGroup] = None,
    ) -> None:
        super().__init__(basic_block, args, type_str, allow_none_bb, yul_source_map, id_group)
        self.base_str = base_str

    @property
    def array_length(self):
        return self.operands[0]


class WriteToMemory(AbstractMemoryInst):
    def __init__(
        self,
        basic_block: Optional[BasicBlock],
        args: List[Value],
        type_str: str,
        allow_none_bb=False,
        yul_source_map: Optional[Tuple] = None,
        id_group: Optional[IdGroup] = None,
    ) -> None:
        super().__init__(basic_block, args, type_str, allow_none_bb, yul_source_map, id_group)
        assert len(args) == 2


class ReadFromMemory(AbstractMemoryInst):
    def __init__(
        self,
        basic_block: Optional[BasicBlock],
        args: List[Value],
        type_str: str,
        allow_none_bb=False,
        yul_source_map: Optional[Tuple] = None,
        id_group: Optional[IdGroup] = None,
    ) -> None:
        super().__init__(basic_block, args, type_str, allow_none_bb, yul_source_map, id_group)
        assert len(args) == 1


class ReadFromCalldata(AbstractMemoryInst):
    def __init__(
        self,
        basic_block: Optional[BasicBlock],
        args: List[Value],
        type_str: str,
        allow_none_bb=False,
        yul_source_map: Optional[Tuple] = None,
        id_group: Optional[IdGroup] = None,
    ) -> None:
        super().__init__(basic_block, args, type_str, allow_none_bb, yul_source_map, id_group)
        assert len(args) == 1


class MemoryArrayLength(AbstractMemoryInst):
    def __init__(
        self,
        basic_block: Optional[BasicBlock],
        args: List[Value],
        type_str: str,
        allow_none_bb=False,
        yul_source_map: Optional[Tuple] = None,
        id_group: Optional[IdGroup] = None,
    ) -> None:
        super().__init__(basic_block, args, type_str, allow_none_bb, yul_source_map, id_group)
        assert len(args) == 1


class CalldataArrayLength(AbstractMemoryInst):
    def __init__(
        self,
        basic_block: Optional[BasicBlock],
        args: List[Value],
        type_str: str,
        allow_none_bb=False,
        yul_source_map: Optional[Tuple] = None,
        id_group: Optional[IdGroup] = None,
    ) -> None:
        super().__init__(basic_block, args, type_str, allow_none_bb, yul_source_map, id_group)
        assert len(args) == 1 if not is_two_args_calldata_ptr(type_str) else len(args) == 2


class MemoryArrayDataslot(AbstractMemoryInst):
    def __init__(
        self,
        basic_block: Optional[BasicBlock],
        args: List[Value],
        type_str: str,
        allow_none_bb=False,
        yul_source_map: Optional[Tuple] = None,
        id_group: Optional[IdGroup] = None,
    ) -> None:
        super().__init__(basic_block, args, type_str, allow_none_bb, yul_source_map, id_group)
        assert len(args) == 1


class CalldataArrayDataslot(AbstractMemoryInst):
    def __init__(
        self,
        basic_block: Optional[BasicBlock],
        args: List[Value],
        type_str: str,
        allow_none_bb=False,
        yul_source_map: Optional[Tuple] = None,
        id_group: Optional[IdGroup] = None,
    ) -> None:
        super().__init__(basic_block, args, type_str, allow_none_bb, yul_source_map, id_group)
        assert len(args) == 1


class MemoryArrayIndexAccess(AbstractMemoryInst):
    def __init__(
        self,
        basic_block: Optional[BasicBlock],
        args: List[Value],
        type_str: str,
        allow_none_bb=False,
        yul_source_map: Optional[Tuple] = None,
        id_group: Optional[IdGroup] = None,
    ) -> None:
        super().__init__(basic_block, args, type_str, allow_none_bb, yul_source_map, id_group)
        assert len(args) == 2


# return_index:0 must be offset
class CallDataArrayIndexAccess(AbstractMemoryInst):
    def __init__(
        self,
        basic_block: Optional[BasicBlock],
        args: List[Value],
        type_str: str,
        return_index: Optional[int],
        return_count: int,
        allow_none_bb=False,
        yul_source_map: Optional[Tuple] = None,
        id_group: Optional[IdGroup] = None,
    ) -> None:
        super().__init__(basic_block, args, type_str, allow_none_bb, yul_source_map, id_group)
        self.return_index = return_index
        self.return_count = return_count
        assert (
            len(args) == 3 or len(args) == 2
        )  # The index for calldata is represented by three arguments (two arguments for static arrays)


class CallDataStructIndexAccess(AbstractMemoryInst):
    def __init__(
        self,
        basic_block: Optional[BasicBlock],
        args: List[Value],
        type_str: str,
        return_index: Optional[int],
        return_count: int,
        allow_none_bb=False,
        yul_source_map: Optional[Tuple] = None,
        id_group: Optional[IdGroup] = None,
    ) -> None:
        super().__init__(basic_block, args, type_str, allow_none_bb, yul_source_map, id_group)
        self.return_index = return_index
        self.return_count = return_count
        assert len(args) == 2


class Concat(AbstractMemoryInst):
    def __init__(
        self,
        basic_block: Optional[BasicBlock],
        args: List[Value],
        type_str: str,
        allow_none_bb=False,
        yul_source_map: Optional[Tuple] = None,
        base_str: Optional[str] = None,
        id_group: Optional[IdGroup] = None,
    ) -> None:
        super().__init__(basic_block, args, type_str, allow_none_bb, yul_source_map, id_group)
        self.base_str = base_str


class CopyLiteral(AbstractMemoryInst):
    def __init__(
        self,
        basic_block: Optional[BasicBlock],
        args: List[Value],
        type_str: str,
        allow_none_bb=False,
        yul_source_map: Optional[Tuple] = None,
        id_group: Optional[IdGroup] = None,
    ) -> None:
        super().__init__(basic_block, args, type_str, allow_none_bb, yul_source_map, id_group)
        assert len(args) == 0


class ConvertStringLiteral(AbstractMemoryInst):
    def __init__(
        self,
        basic_block: Optional[BasicBlock],
        args: List[Value],
        type_str: str,
        allow_none_bb=False,
        yul_source_map: Optional[Tuple] = None,
        id_group: Optional[IdGroup] = None,
    ) -> None:
        super().__init__(basic_block, args, type_str, allow_none_bb, yul_source_map, id_group)
        assert len(args) == 0


class ConvertReference(AbstractMemoryInst):
    def __init__(
        self,
        basic_block: Optional[BasicBlock],
        args: List[Value],
        type_str: str,
        allow_none_bb=False,
        yul_source_map: Optional[Tuple] = None,
        id_group: Optional[IdGroup] = None,
    ) -> None:
        super().__init__(basic_block, args, type_str, allow_none_bb, yul_source_map, id_group)
        # calldataptr args==2, storageptr args==1
        assert (len(args) == 2 and is_two_args_calldata_ptr(type_str) and "calldata_ptr" in type_str) or (
            len(args) == 1 and ("storage" in type_str) or (not is_two_args_calldata_ptr(type_str))
        )


class CopyArray(AbstractMemoryInst):
    def __init__(
        self,
        basic_block: Optional[BasicBlock],
        args: List[Value],
        type_str: str,
        allow_none_bb=False,
        yul_source_map: Optional[Tuple] = None,
        id_group: Optional[IdGroup] = None,
    ) -> None:
        super().__init__(basic_block, args, type_str, allow_none_bb, yul_source_map, id_group)
        assert len(args) == 1 or len(args) == 2


class ExtractReturnData(AbstractMemoryInst):
    def __init__(
        self,
        basic_block: Optional[BasicBlock],
        args: List[Value],
        type_str: str,
        allow_none_bb=False,
        yul_source_map: Optional[Tuple] = None,
        id_group: Optional[IdGroup] = None,
    ) -> None:
        super().__init__(basic_block, args, type_str, allow_none_bb, yul_source_map, id_group)
        assert len(args) == 0


class ABIEncode(AbstractMemoryInst):
    def __init__(
        self,
        basic_block: Optional[BasicBlock],
        args: List[Value],
        type_str: str,
        allow_none_bb,
        yul_source_map: Optional[Tuple] = None,
        is_packed: Optional[bool] = None,
        id_group: Optional[IdGroup] = None,
    ) -> None:
        super().__init__(basic_block, args, type_str, allow_none_bb, yul_source_map, id_group)
        assert len(args) > 0
        assert is_packed is not None
        self.is_packed = is_packed


class ABIDecodeFromMemory(AbstractMemoryInst):
    def __init__(  # from memory
        self,
        basic_block: Optional[BasicBlock],
        args: List[Value],
        type_str: str,
        return_index,
        return_count,
        allow_none_bb,
        yul_source_map: Optional[Tuple] = None,
        id_group: Optional[IdGroup] = None,
    ) -> None:
        super().__init__(basic_block, args, type_str, allow_none_bb, yul_source_map, id_group)
        self.return_index = return_index
        self.return_count = return_count
        assert len(args) >= 0

    def info(self):
        return str(type(self)) + " return index:" + str(self.return_index) + " return count:" + str(self.return_count)


# If a function starts with abi_decode and does not end with fromMemory, it means that the data is coming from calldata
class ABIDecodeFromCallData(AbstractMemoryInst):
    def __init__(  # from calldata
        self,
        basic_block: Optional[BasicBlock],
        args: List[Value],
        type_str: str,
        return_index,
        return_count,
        calldata_ptr_offset: bool,
        calldata_ptr_length: bool,
        calldata_ptr_count: int,
        allow_none_bb,
        yul_source_map: Optional[Tuple] = None,
        source_args_index: Optional[int] = None,
        id_group: Optional[IdGroup] = None,
    ) -> None:
        super().__init__(basic_block, args, type_str, allow_none_bb, yul_source_map, id_group)
        self.return_index = return_index
        self.return_count = return_count
        self.is_calldata_ptr_offset = calldata_ptr_offset
        self.is_calldata_ptr_length = calldata_ptr_length
        self.calldata_ptr_count = calldata_ptr_count
        self.source_args_index = source_args_index
        assert len(args) > 0

    def info(self):
        return str(type(self)) + " return index:" + str(self.return_index) + " return count:" + str(self.return_count)


def memory_function_to_insts_and_returns(
    inst: Union[CallInst, YulFuncInst]
) -> Tuple[Optional[List[Instruction]], Optional[List[int]]]:
    if isinstance(inst, CallInst):
        name = inst.called_function.name
    else:
        assert isinstance(inst, YulFuncInst)
        name = inst.name
        assert (
            name.startswith("abi_decode_tuple")
            or name.startswith("calldata_array_index_access")
            or name.startswith("access_calldata_tail")
        )
    if name.startswith("allocate_and_zero_memory_array"):
        base_str = "allocate_and_zero_memory_array"
        type_str = name[len(base_str) + 1 :]
        assert type_str.startswith("t_")
        new_inst = AllocateMemory(
            None,
            inst.arguments,
            base_str,
            type_str,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            id_group=inst.id_group,
        )
        return [new_inst], [0]
    elif name.startswith("allocate_memory_array"):
        base_str = "allocate_memory_array"
        type_str = name[len(base_str) + 1 :]
        assert type_str.startswith("t_")
        new_inst = AllocateMemory(
            None,
            inst.arguments,
            base_str,
            type_str,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            id_group=inst.id_group,
        )
        return [new_inst], [0]

    elif name.startswith("allocate_memory_struct"):
        base_str = "allocate_memory_struct"
        type_str = name[len(base_str) + 1 :]
        assert type_str.startswith("t_")
        new_inst = AllocateMemory(
            None,
            inst.arguments,
            base_str,
            type_str,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            id_group=inst.id_group,
        )
        return [new_inst], [0]
    elif name.startswith("zero_value_for_split_t_struct"):
        base_str = "zero_value_for_split"
        type_str = name[len(base_str) + 1 :]
        assert type_str.startswith("t_")
        new_inst = AllocateMemory(
            None,
            inst.arguments,
            base_str,
            type_str,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            id_group=inst.id_group,
        )
        return [new_inst], [0]

    elif name.startswith("zero_value_for_split_"):
        base_str = "zero_value_for_split"
        type_str = name[len(base_str) + 1 :]
        if not type_str.endswith("memory_ptr"):
            return None, None
        assert type_str.startswith("t_")

        new_inst = AllocateMemory(
            None,
            inst.arguments,
            base_str,
            type_str,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            id_group=inst.id_group,
        )
        return [new_inst], [0]
    elif name.startswith("write_to_memory"):
        type_str = name[len("write_to_memory") + 1 :]
        assert type_str.startswith("t_")
        new_inst = WriteToMemory(
            None,
            inst.arguments,
            type_str,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            id_group=inst.id_group,
        )
        return [new_inst], [0]
    elif name.startswith("read_from_memory"):
        type_str = name[len("read_from_memory") :]
        assert type_str.startswith("t_")
        new_inst = ReadFromMemory(
            None,
            inst.arguments,
            type_str,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            id_group=inst.id_group,
        )
        return [new_inst], [0]
    elif name.startswith("read_from_calldata"):
        type_str = name[len("read_from_calldata") :]
        assert type_str.startswith("t_")
        new_inst = ReadFromCalldata(
            None,
            inst.arguments,
            type_str,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            id_group=inst.id_group,
        )
        return [new_inst], [0]

    elif name.startswith("memory_array_index_access"):
        type_str = name[len("memory_array_index_access") + 1 :]
        assert type_str.startswith("t_")
        new_inst = MemoryArrayIndexAccess(
            None,
            inst.arguments,
            type_str,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            id_group=inst.id_group,
        )
        return [new_inst], [0]

    elif name.startswith("calldata_array_index_access"):
        type_str = name[len("calldata_array_index_access") + 1 :]
        assert type_str.startswith("t_")
        assert isinstance(inst, YulFuncInst)
        new_inst = CallDataArrayIndexAccess(
            None,
            inst.arguments,
            type_str,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            return_index=inst.return_index,
            return_count=inst.return_count,
            id_group=inst.id_group,
        )
        return [new_inst], [0]

    elif name.startswith("access_calldata_tail"):  # calldata, access for struct
        type_str = name[len("access_calldata_tail") + 1 :]
        assert type_str.startswith("t_")
        assert isinstance(inst, YulFuncInst)
        new_inst = CallDataStructIndexAccess(
            None,
            inst.arguments,
            type_str,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            return_index=inst.return_index,
            return_count=inst.return_count,
            id_group=inst.id_group,
        )
        return [new_inst], [0]
    elif name.startswith("extract_returndata"):
        type_str = "t_bytes_memory_ptr"
        assert type_str.startswith("t_")
        new_inst = ExtractReturnData(
            None,
            inst.arguments,
            type_str,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            id_group=inst.id_group,
        )
        return [new_inst], [0]

    elif name.startswith("abi_encode_tuple_packed_"):
        type_str = name[24:]
        assert type_str.startswith("t_")
        new_inst = ABIEncode(
            None,
            inst.arguments,
            type_str,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            is_packed=True,
            id_group=inst.id_group,
        )
        return [new_inst], [0]

    elif name.startswith("abi_encode_tuple_"):  # abi_encode_tuple__to if no return
        type_str = name[17:]
        assert type_str.startswith("t_") or type_str.startswith("_to_")
        new_inst = ABIEncode(
            None,
            inst.arguments,
            type_str,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            is_packed=False,
            id_group=inst.id_group,
        )
        return [new_inst], [0]

    elif name.startswith("abi_decode_tuple") and name.endswith("_fromMemory"):  # read from memory
        assert isinstance(inst, YulFuncInst)
        assert inst.return_index is not None
        type_str = name[17:]
        # pare name from return_index
        type_str_with_tail = type_str
        assert type_str_with_tail.startswith("t_")
        type_tuple_list, tail_str = TypeParser.parse_multi_type_str(type_str_with_tail)
        type_index = inst.return_index
        assert type_index < inst.return_count
        type_tuple = type_tuple_list[type_index]
        type_str = TypeParser.parse_result_to_str(type_tuple)

        assert type_str.startswith("t_")
        new_inst = ABIDecodeFromMemory(
            None,
            inst.arguments,
            type_str,
            inst.return_index,
            inst.return_count,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            id_group=inst.id_group,
        )
        return [new_inst], [0]

    elif name.startswith("abi_decode_tuple") and not name.endswith("_fromMemory"):
        assert isinstance(inst, YulFuncInst)
        assert inst.return_index is not None
        type_str = name[17:]
        assert type_str.startswith("t_")

        type_str_with_tail = type_str
        assert type_str_with_tail.startswith("t_")
        type_tuple_list, tail_str = TypeParser.parse_multi_type_str(type_str_with_tail)

        assert inst.return_index < inst.return_count
        type_index = inst.return_index - inst.calldata_ptr_count
        type_tuple = type_tuple_list[type_index]
        type_str = TypeParser.parse_result_to_str(type_tuple)

        new_inst = ABIDecodeFromCallData(
            None,
            inst.arguments,
            type_str,
            inst.return_index,
            inst.return_count,
            inst.calldata_ptr_offset,
            inst.calldata_ptr_length,
            inst.calldata_ptr_count,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            source_args_index=type_index,
            id_group=inst.id_group,
        )
        return [new_inst], [0]

    elif name.startswith("string_concat"):
        base_str = "string_concat"
        type_str = name[len("string_concat") + 1 :]
        assert type_str.startswith("t_")
        new_inst = Concat(
            None,
            inst.arguments,
            type_str,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            base_str=base_str,
            id_group=inst.id_group,
        )
        return [new_inst], [0]

    elif name.startswith("bytes_concat"):
        base_str = "bytes_concat"
        type_str = name[len("bytes_concat") + 1 :]
        assert type_str.startswith("t_")
        new_inst = Concat(
            None,
            inst.arguments,
            type_str,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            base_str=base_str,
            id_group=inst.id_group,
        )
        return [new_inst], [0]

    elif name.startswith("convert_array"):
        base_str = "convert_array"
        type_str = name[len("convert_array") + 1 :]
        assert type_str.startswith("t_")
        new_inst = ConvertReference(
            None,
            inst.arguments,
            type_str,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            id_group=inst.id_group,
        )
        return [new_inst], [0]

    elif name.startswith("convert_t_struct"):
        base_str = "convert_t_struct"
        type_str = name[len("convert") + 1 :]
        new_inst = ConvertReference(
            None,
            inst.arguments,
            type_str,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            id_group=inst.id_group,
        )
        return [new_inst], [0]

    elif name.startswith("convert_t_stringliteral"):
        base_str = "convert_t_stringliteral"
        type_str = name[len("convert") + 1 :]
        new_inst = ConvertStringLiteral(
            None,
            inst.arguments,
            type_str,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            id_group=inst.id_group,
        )
        return [new_inst], [0]

    elif name.startswith("copy_array_from_storage_to_memory"):
        base_str = "copy_array_from_storage_to_memory"
        type_str = name[len("copy_array_from_storage_to_memory") + 1 :]
        new_inst = CopyArray(
            None,
            inst.arguments,
            type_str,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            id_group=inst.id_group,
        )
        return [new_inst], [0]
    elif name.startswith("read_from_storage__dynamic_split"):
        base_str = "read_from_storage__dynamic_split"
        type_str = name[len("read_from_storage__dynamic_split") + 1 :]
        new_inst = CopyArray(
            None,
            inst.arguments,
            type_str,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            id_group=inst.id_group,
        )
        return [new_inst], [0]

    elif name.startswith("try_decode_error_message"):
        base_str = "try_decode_error_message"
        type_str = "t_string_memory_ptr"
        new_inst = ExtractReturnData(
            None,
            inst.arguments,
            type_str,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            id_group=inst.id_group,
        )
        return [new_inst], [0]

    elif name.startswith("copy_arguments_for_constructor"):
        return None, None

    elif name == "allocate_memory":
        base_str = "allocate_memory"
        type_str = "t_bytes_memory_ptr"
        new_inst = AllocateMemory(
            None,
            inst.arguments,
            base_str,
            type_str,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            id_group=inst.id_group,
        )
        return [new_inst], [0]

    elif name.startswith("copy_literal_to_memory"):
        base_str = "copy_literal_to_memory"
        type_str = name[len("copy_literal_to_memory") + 1 :]  # type_str is string hash
        new_inst = CopyLiteral(
            None,
            inst.arguments,
            type_str,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            id_group=inst.id_group,
        )
        return [new_inst], [0]

    elif name.startswith("array_length") and name.endswith("memory_ptr"):
        base_str = "array_length"
        type_str = name[len("array_length") + 1 :]
        new_inst = MemoryArrayLength(
            None,
            inst.arguments,
            type_str,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            id_group=inst.id_group,
        )
        return [new_inst], [0]

    elif name.startswith("array_length") and name.endswith("calldata_ptr"):
        base_str = "array_length"
        type_str = name[len("array_length") + 1 :]
        new_inst = CalldataArrayLength(
            None,
            inst.arguments,
            type_str,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            id_group=inst.id_group,
        )
        return [new_inst], [0]

    elif name.startswith("array_dataslot") and name.endswith("memory_ptr"):
        base_str = "array_dataslot"
        type_str = name[len("array_dataslot") + 1 :]
        new_inst = MemoryArrayDataslot(
            None,
            inst.arguments,
            type_str,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            id_group=inst.id_group,
        )
        return [new_inst], [0]

    elif name.startswith("array_dataslot") and name.endswith("calldata_ptr"):
        base_str = "array_dataslot"
        type_str = name[len("array_dataslot") + 1 :]
        new_inst = CalldataArrayDataslot(
            None,
            inst.arguments,
            type_str,
            allow_none_bb=True,
            yul_source_map=inst.yul_source_map,
            id_group=inst.id_group,
        )
        return [new_inst], [0]
    else:
        return None, None


all_memory_instructions = [
    AllocateMemory,
    WriteToMemory,
    ReadFromMemory,
    ReadFromCalldata,
    MemoryArrayIndexAccess,
    CallDataArrayIndexAccess,
    CallDataStructIndexAccess,
    Concat,
    CopyLiteral,
    ConvertStringLiteral,
    ConvertReference,
    CopyArray,
    ExtractReturnData,
    ABIEncode,
    ABIDecodeFromMemory,
    ABIDecodeFromCallData,
    MemoryArrayLength,
    CalldataArrayLength,
    MemoryArrayDataslot,
    CalldataArrayDataslot,
]

all_memory_instructions_dict = {memory_inst.__class__.__name__: memory_inst for memory_inst in all_memory_instructions}
