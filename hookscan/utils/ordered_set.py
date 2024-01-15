from typing import Any, Iterable, MutableSet, Optional, TypeVar

_T = TypeVar("_T")


class OrderedSet(MutableSet[_T]):
    def __init__(self, __iterable: Optional[Iterable[_T]] = None) -> None:
        super().__init__()
        if __iterable is None:
            self._data = {}
        else:
            self._data = {x: None for x in __iterable}

    def __len__(self) -> int:
        return len(self._data)

    def __contains__(self, x: _T) -> bool:
        return x in self._data

    def isdisjoint(self, other: Iterable[_T]) -> bool:
        return all(x not in self._data for x in other)

    def issubset(self, other: Iterable[_T]) -> bool:
        other_set = set(other)
        return all(x in other_set for x in self._data)

    def issuperset(self, other: Iterable[_T]) -> bool:
        return all(x in self._data for x in other)

    def copy(self) -> "OrderedSet[_T]":
        c = OrderedSet()
        c._data = self._data.copy()
        return c

    def union(self, other: Iterable[_T]) -> "OrderedSet[_T]":
        c = self.copy()
        for x in other:
            c._data[x] = None
        return c

    def intersection(self, other: Iterable[_T]) -> "OrderedSet[_T]":
        return OrderedSet(x for x in other if x in self._data)

    def difference(self, other: Iterable[_T]) -> "OrderedSet[_T]":
        c = self.copy()
        for x in other:
            c.discard(x)
        return c

    def update(self, other: Iterable[_T]) -> None:
        for x in other:
            self._data[x] = None

    def intersection_update(self, other: Iterable[_T]) -> None:
        other_set = set(other)
        to_del = [x for x in self if x not in other_set]
        self.difference_update(to_del)

    def difference_update(self, other: Iterable[_T]) -> None:
        for x in other:
            self.discard(x)

    __or__ = union
    __and__ = intersection
    __sub__ = difference

    def __ior__(self, other: Iterable[_T]) -> "OrderedSet[_T]":
        self.update(other)
        return self

    def __iand__(self, other: Iterable[_T]) -> "OrderedSet[_T]":
        self.intersection_update(other)
        return self

    def __isub__(self, other: Iterable[_T]) -> "OrderedSet[_T]":
        self.difference_update(other)
        return self

    def add(self, elem: _T) -> None:
        self._data[elem] = None

    def remove(self, elem: _T) -> None:
        del self._data[elem]

    def discard(self, elem: _T) -> None:
        try:
            del self._data[elem]
        except KeyError:
            pass

    def pop(self) -> _T:
        return self._data.popitem()[0]

    def clear(self) -> None:
        self._data.clear()

    def __hash__(self):
        raise TypeError("unhashable type: 'OrderedSet'")

    def __eq__(self, other: Any) -> bool:
        return super().__eq__(other)

    def __iter__(self):
        return iter(self._data.keys())

    def __repr__(self) -> str:
        return f"OrderedSet({list(self._data.keys())})"
