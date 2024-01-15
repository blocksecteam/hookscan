from typing import TYPE_CHECKING, List, Optional

from hookscan.components.value import Value
from hookscan.utils.ordered_set import OrderedSet as set

if TYPE_CHECKING:
    from hookscan.core.traversal import PathNode
    from hookscan.core.traversal_info import TraversalInfo


class ValueInstance:
    def __init__(
        self, value: Value, path_node: Optional["PathNode"] = None, info: Optional["TraversalInfo"] = None
    ) -> None:
        self.value = value
        self.operand_instances: List["ValueInstance"] = []
        self.taints = set()
        self._origin: Optional[ValueInstance] = None
        self.type_str: Optional[str] = None
        self.function_signature: Optional[int] = None
        self.path_node: Optional[PathNode] = path_node
        self.call_args: List[ValueInstance] = []
        self.info = info

    @property
    def origin(self) -> "ValueInstance":
        if self._origin is None:
            return self
        return self._origin

    @origin.setter
    def origin(self, arg):
        raise Exception("use propagate_from instead")

    def propagate_from(self, other: "ValueInstance"):
        self.taints.update(other.taints)
        self._origin = other.origin
        self.type_str = other.type_str

    def __repr__(self):
        return f"instance of {self.value} at {id(self)}"
