from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, List, Optional, Tuple

from uniscan.components.basic_block import BasicBlock
from uniscan.components.instruction import CallInst
from uniscan.components.value import Argument, User

if TYPE_CHECKING:
    from uniscan.components.contract import Contract


class FunctionType(Enum):
    CREATION = 1
    CONSTRUCTOR = 2
    RUNTIME = 3
    CONSTANT = 4
    GETTER = 5
    MODIFIER = 6
    EXTERNAL = 7
    INTERNAL = 8
    # NOTE type of "receive" is also FALLBACK
    FALLBACK = 9
    YUL_FUNCTION = 10


@dataclass
class MutabilityInfo:
    _payable: Optional[bool] = None
    non_static_call: bool = False
    storage_write: bool = False
    log: bool = False
    self_destruct: bool = False

    def update(self, other: "MutabilityInfo") -> None:
        """
        Note: "Payable" will not be updated.
        """
        if not self.non_static_call:
            self.non_static_call = other.non_static_call
        if not self.storage_write:
            self.storage_write = other.storage_write
        if not self.log:
            self.log = other.log
        if not self.self_destruct:
            self.self_destruct = other.self_destruct


class Function(User):
    def __init__(self, contract: "Contract") -> None:
        super().__init__(contract.id_group)
        self.contract = contract
        self.name: str
        self.type: FunctionType
        self.selector: Optional[int] = None
        self.yul_source_map: Optional[Tuple] = None
        # NOTE runtime or creation
        self.is_runtime: bool
        self.arguments: List[Argument] = []
        self.return_names: List[str] = []

        self.entry_point: BasicBlock
        self.return_instructions = []

        self.has_dead_code: bool = False

        self.basic_blocks: List[BasicBlock] = []
        self.mutability_info: MutabilityInfo = MutabilityInfo()

    @property
    def payable(self) -> bool:
        if self.type in [FunctionType.CONSTRUCTOR, FunctionType.CREATION]:
            raise NotImplementedError("constructor currently no payable info")
        elif self.type not in [FunctionType.EXTERNAL, FunctionType.FALLBACK]:
            raise ValueError("this function has no payable info")

        if self.mutability_info._payable is None:
            raise ValueError("payable info not set")
        return self.mutability_info._payable

    @property
    def mutable(self) -> bool:
        return (
            self.mutability_info.non_static_call
            or self.mutability_info.storage_write
            or self.mutability_info.log
            or self.mutability_info.self_destruct
        )

    @property
    def mutable_or_payable(self) -> bool:
        # NOTE put payable later to reduce Exception
        return self.mutable or self.payable

    @property
    def has_return(self) -> bool:
        return bool(self.return_instructions)

    @property
    def return_count(self) -> int:
        return len(self.return_names)

    def info(self):
        block_infos = [b.info() for b in self.basic_blocks]
        return {
            "function_name": self.name,
            "entry_point": self.entry_point.id,
            "basic_blocks": block_infos,
        }

    def __str__(self):
        return "Function %s" % self.name

    def __repr__(self):
        return "Function %s" % self.name

    @property
    def solidity_name(self):
        if self.type == FunctionType.FALLBACK:
            return "(FALLBACK_OR_RECEIVE)"
        elif self.type == FunctionType.EXTERNAL:
            return "_".join(self.name.split("_")[2:-1])
        elif self.type == FunctionType.INTERNAL:
            return "_".join(self.name.split("_")[1:-1])
        else:
            return None

    def get_internal_function_source_map(self):
        if self.type != FunctionType.EXTERNAL:
            return None
        for bb in self.basic_blocks:
            for inst in bb.instructions:
                if not isinstance(inst, CallInst):
                    continue
                if self.name.endswith(inst.called_function.name):
                    return inst.called_function.yul_source_map
        return None
