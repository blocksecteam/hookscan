from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Optional, Tuple

if TYPE_CHECKING:
    from uniscan.components.function import Function

from uniscan.components.unique_id import IdGroup, UniqueId

"""
class inheritance:
    UniqueId <- Value <- User

    User <- Argument
    User <- Constant
    User <- Instruction
    User <- Function
    User <- BasicBlock
"""


class Value(UniqueId):
    def __init__(self, id_group: IdGroup) -> None:
        super().__init__(id_group)
        self.users: List[User] = []

        self.yul_source_map: Optional[Tuple] = None
        self._comment: Optional[str] = None
        self._source_code_source_map: Optional[dict] = None
        self._source_code = None
        self._source_code_info = None
        self._is_assembly = None

    @property
    def comment(self):
        if self._comment is not None:
            return self._comment
        else:
            self._comment = self._try_to_get_comment()
            return self._comment

    def _try_to_get_comment(self) -> Optional[str]:
        yul_source_map = self.yul_source_map
        if hasattr(self, "get_internal_function_source_map"):
            internal_function_source_map = self.get_internal_function_source_map()  # pyright: ignore
            if internal_function_source_map is not None:
                yul_source_map = internal_function_source_map
        if yul_source_map is None:
            return None
        if not hasattr(self, "contract"):
            return None
        contract = self.contract  # pyright: ignore
        yul_content: List[str] = contract.yul_list_by_line
        line = yul_source_map[0] - 1
        while line >= 0:
            tmp_content = yul_content[line]
            if tmp_content.replace(" ", "").startswith("///@src"):
                return yul_content[line]
            else:
                line -= 1
        return None

    @property
    def source_code_source_map(self) -> Optional[dict]:
        if self._source_code_source_map is not None:
            return self._source_code_source_map
        else:
            self._source_code_source_map = self._try_to_get_source_code_source_map()
            return self._source_code_source_map

    def _try_to_get_source_code_source_map(self) -> Optional[dict]:
        comment = self.comment
        if comment is None:
            return None
        else:
            file_number, start_offset, end_offset = self._get_source_code_source_map_info(comment)
            return {"file_number": file_number, "start_offset": start_offset, "end_offset": end_offset}

    def _get_source_code_source_map_info(self, comment) -> Tuple[str, str, str]:
        tmp_items = comment.split(":")
        file_number = tmp_items[0].split(" ")[-1]
        start_offset = tmp_items[1]
        end_offset = tmp_items[2].split(" ")[0]
        return file_number, start_offset, end_offset

    @property
    def source_code(self) -> Optional[str]:
        if self._source_code is not None:
            return self._source_code
        else:
            self._source_code = self._try_to_get_source_code()
            return self._source_code

    def _try_to_get_source_code(self) -> Optional[str]:
        comment = self.comment
        if comment is None:
            return None
        else:
            return self._get_source_code(comment)

    def _get_source_code(self, comment) -> str:
        tmp_items = comment.split('"')
        result = ""
        for i, item in enumerate(tmp_items):
            if i == 0:
                continue
            else:
                result += item
        return result

    @property
    def source_code_info(self) -> Optional[Dict[str, Any]]:
        if not hasattr(self, "contract"):
            return None
        if self.contract.std_in_json is None:  # pyright: ignore
            return None
        if self._source_code_info is not None:
            return self._source_code_info
        else:
            if self.comment is not None:
                file_name = self._get_file_name(self.source_code_source_map["file_number"])  # pyright: ignore
                row_number, col_offset = self._pretty_offset(self.source_code_source_map, file_name)
                self._source_code_info = {
                    "file_name": file_name,
                    "row_number": row_number,
                    "col_offset": col_offset,
                    "source_code": self.source_code,
                }
                return self._source_code_info

    def _get_file_name(self, file_number) -> str:
        return self.contract.file_name_map[file_number]  # pyright: ignore

    def _pretty_offset(self, source_code_source_map, file_name) -> Tuple[int, int]:
        def _calculate_line_column(code_bytes: bytes) -> Tuple[int, int]:
            lines = code_bytes.splitlines(keepends=True)
            if len(lines) == 0:
                line, column = 0, 0
            elif lines[-1].endswith(b"\n"):
                line, column = len(lines), 0
            else:
                line, column = len(lines) - 1, len((lines[-1]).decode("utf-8"))
            return line + 1, column + 1

        start_offset = int(source_code_source_map["start_offset"])
        src = self.contract.std_in_json["sources"][file_name]["content"]  # pyright: ignore
        src_bytes = bytes(src, "utf-8")
        return _calculate_line_column(src_bytes[0 : int(start_offset)])

    @property
    def is_assembly(self):
        if self._is_assembly is not None:
            return self._is_assembly
        else:
            if self.comment is not None:
                if self.source_code.startswith("assembly"):  # pyright: ignore
                    self._is_assembly = True
                else:
                    self._is_assembly = False
        return self._is_assembly


class User(Value):
    def __init__(self, id_group: IdGroup) -> None:
        super().__init__(id_group)
        self.operands: List[Value] = []

    def use(self, value: Value):
        self.operands.append(value)
        value.users.append(self)

    def replace_operand(self, i: int, value: Value):
        old_operand = self.operands[i]
        old_operand.users = [u for u in old_operand.users if u != self]
        self.operands[i] = value
        value.users.append(self)

    def use_all(self, values: Iterable[Value]):
        self.operands.extend(values)
        for value in values:
            value.users.append(self)

    def unuse_all_operands(self):
        for operand in self.operands:
            operand.users = [u for u in operand.users if u != self]
        self.operands.clear()


class Argument(User):
    def __init__(self, name: str, index: int, func: "Function") -> None:
        super().__init__(func.id_group)
        self.name = name
        self.index = index
        self.function = func
