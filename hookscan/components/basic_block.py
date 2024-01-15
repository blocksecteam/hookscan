from typing import TYPE_CHECKING, List, Optional

from hookscan.components.instruction import Instruction
from hookscan.components.value import User

if TYPE_CHECKING:
    from hookscan.components.function import Function


class BasicBlock(User):
    def __init__(
        self,
        function: "Function",
        last_loop_entry: "BasicBlock",
        is_loop_entry=False,
        loop_compare=None,
        do_while_compare=None,
    ) -> None:
        """
        Args:
            last_loop_entry: current_loop_entry if bb != loop_entry
            loop_compare: None if bb != loop_entry
            do_while_compare: None if bb != loop_entry
        """
        super().__init__(function.id_group)
        self.function = function
        function.basic_blocks.append(self)
        self.is_loop_entry = is_loop_entry
        self._last_loop_entry = last_loop_entry
        self.loop_compare = loop_compare
        self.do_while_compare = do_while_compare
        self.terminator: Optional[Instruction] = None
        self.instructions: List[Instruction] = []
        self.predecessors: List["BasicBlock"] = []
        self.successors: List["BasicBlock"] = []

    @property
    def is_loop_compare(self):
        current_loop_entry = self.current_loop_entry
        # NOTE loop_compare can be None
        return (
            current_loop_entry is not None
            and current_loop_entry.loop_compare is not None
            and current_loop_entry.loop_compare == self
        )

    @property
    def is_do_while_compare(self):
        current_loop_entry = self.current_loop_entry
        return (
            current_loop_entry is not None
            and current_loop_entry.do_while_compare is not None
            and current_loop_entry.do_while_compare == self
        )

    @property
    def current_loop_entry(self):
        if self.is_loop_entry:
            return self
        else:
            return self._last_loop_entry

    def info(self):
        preds = [x.id for x in self.predecessors]
        succs = [x.id for x in self.successors]
        insts = [x.info() for x in self.instructions]
        return {
            "basic_block_id": self.id,
            "predecessors": preds,
            "successors": succs,
            "instructions": insts,
        }

    def __repr__(self):
        return f"BB %{self.id} in {self.function.name}"
