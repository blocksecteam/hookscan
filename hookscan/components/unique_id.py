from typing import List


class IdGroup:
    def __init__(self):
        self.elements: List["UniqueId"] = []

    def add(self, element: "UniqueId") -> int:
        self.elements.append(element)
        return len(self.elements) - 1


class UniqueId:
    def __init__(self, id_group: IdGroup) -> None:
        self.id_group = id_group
        self.id = id_group.add(self)

    def __eq__(self, __o: object) -> bool:
        if not isinstance(__o, UniqueId):
            raise TypeError(f"cannot compare UniqueId with {type(__o).__name__}")
        return self.id_group == __o.id_group and self.id == __o.id

    def __hash__(self) -> int:
        return hash(self.id_group) + self.id

    def info_rvalue(self):
        return f"%{self.id}"

    def __repr__(self):
        return self.info_rvalue()
