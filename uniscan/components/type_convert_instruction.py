from typing import Iterable, Optional, Tuple

from uniscan.components.basic_block import BasicBlock
from uniscan.components.instruction import Instruction
from uniscan.components.unique_id import IdGroup
from uniscan.components.value import Value


class TypeConvertInstruction(Instruction):
    def __init__(
        self,
        basic_block: Optional["BasicBlock"],
        from_type_str: str,
        to_type_str: str,
        args: Iterable[Value],
        allow_none_bb=False,
        yul_source_map: Optional[Tuple] = None,
        id_group: Optional[IdGroup] = None,
    ) -> None:
        super().__init__(basic_block, allow_none_bb=allow_none_bb, yul_source_map=yul_source_map, id_group=id_group)
        self.from_type_str = from_type_str
        self.to_type_str = to_type_str
        self.use_all(args)

    @property
    def arguments(self):
        return self.operands

    def info(self):
        args = ", ".join(
            (x.info_rvalue() if hasattr(x, "info_rvalue") else "?") for x in self.arguments  # pyright: ignore
        )
        return f"%{self.id} = convert {args} to {self.to_type_str}"
