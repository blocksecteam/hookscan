import re
from typing import List, Tuple

r"""
t_address(_payable)?
t_array\$_`type`_\$(\d+|dyn)_`location`
t_bool
t_bytes\d+
t_bytes_`location`
t_contract\$_`identifier`_\$\d+
t_enum\$_`identifier`_\$\d+
t_function_(internal|external)_(view|pure|payable|nonpayable)\$_(`type`(_\$_`type`)*)?_\$returns\$_(`type`(_\$_`type`)*)?_\$
t_(u)?int\d+
t_mapping\$_`type`_\$_`type`_\$
t_rational_(minus_)?\d+_by_\d+
t_string_`location`
t_stringliteral_[a-f0-9]{64}
t_struct\$_`identifier`_\$\d+_`location`
t_tuple\$_(`type`(_\$_`type`)*)?_\$
"""

simple_re_strings = [
    r"t_address(_payable)?",
    r"t_bool",
    r"t_bytes\d+",
    r"t_bytes_`location`",
    r"t_contract\$_`identifier`_\$\d+",
    r"t_enum\$_`identifier`_\$\d+",
    r"t_int\d+",
    r"t_uint\d+",
    r"t_rational_(minus_)?\d+_by_\d+",
    r"t_string_`location`",
    r"t_stringliteral_[a-fA-F0-9]{64}",
    r"t_struct\$_`identifier`_\$\d+_`location`",
    r"t_userDefinedValueType\$_`identifier`_\$\d+",
]

_complex_re_strings = [
    r"t_array\$_`type`_\$(\d+|dyn)_`location`",
    r"t_function_(internal|external)_(view|pure|payable|nonpayable)\$_(`type`(_\$_`type`)*)?_\$returns\$_(`type`(_\$_`type`)*)?_\$",
    r"t_mapping\$_`type`_\$_`type`_\$",
    r"t_tuple\$_(`type`(_\$_`type`)*)?_\$",
]

location_strings = [
    "memory_ptr",
    "calldata_ptr",
    "storage_ptr",
    "storage",
]

simple_re_list = [
    re.compile(s.replace("`location`", "(" + "|".join(location_strings) + ")").replace("`identifier`", r"[\w\$.]+?"))
    for s in simple_re_strings
]

array_head_str = "t_array$_"
array_tail_re = re.compile(r"_\$(\d+|dyn)_`location`".replace("`location`", "(" + "|".join(location_strings) + ")"))
function_head_re = re.compile(r"t_function_(internal|external)_(view|pure|payable|nonpayable)\$_")
type_separator_str = "_$_"
type_end_str = "_$"
function_mid_str = "_$returns$_"
mapping_head_str = "t_mapping$_"
tuple_head_str = "t_tuple$_"


class TypeParser:
    @classmethod
    def parse_type_list_str_with_tail(
        cls, full_str: str, separator: str = type_separator_str
    ) -> Tuple[List[Tuple], str]:
        """
        Return a list of type_str and a tail_str.
        """
        type_list = []
        tail_str = full_str
        if tail_str.startswith("t_"):
            while True:
                type_tuple, tail_str = cls.parse_type_str_with_tail(tail_str)
                type_list.append(type_tuple)
                if tail_str.startswith(separator + "t_"):
                    tail_str = tail_str[len(separator) :]
                else:
                    break
        return type_list, tail_str

    @classmethod
    def parse_type_str_with_tail(cls, full_str: str) -> Tuple[Tuple, str]:
        """
        Return a type_str and a tail_str.
        """
        assert full_str.startswith("t_")
        for pattern in simple_re_list:
            m = pattern.match(full_str)
            if m:
                start, end = m.span()
                assert start == 0
                return (full_str[:end],), full_str[end:]
        if full_str.startswith(array_head_str):
            sub_type_str, tail_str = cls.parse_type_str_with_tail(full_str[len(array_head_str) :])
            m = array_tail_re.match(tail_str)
            assert m
            array_tail_str = m.group()
            tail_str = tail_str[len(array_tail_str) :]
            return (array_head_str, sub_type_str, array_tail_str), tail_str
        elif full_str.startswith(mapping_head_str):
            sub_type_str_1, tail_str = cls.parse_type_str_with_tail(full_str[len(mapping_head_str) :])
            assert tail_str.startswith(type_separator_str)
            sub_type_str_2, tail_str = cls.parse_type_str_with_tail(tail_str[len(type_separator_str) :])
            assert tail_str.startswith(type_end_str)
            tail_str = tail_str[len(type_end_str) :]
            return (
                mapping_head_str,
                sub_type_str_1,
                type_separator_str,
                sub_type_str_2,
                type_end_str,
            ), tail_str
        elif full_str.startswith(tuple_head_str):
            tail_str = full_str[len(tuple_head_str) :]
            sub_type_list, tail_str = cls.parse_type_list_str_with_tail(tail_str, type_separator_str)
            assert tail_str.startswith(type_end_str)
            tail_str = tail_str[len(type_end_str) :]
            return (tuple_head_str, sub_type_list, type_end_str), tail_str
        else:
            m = function_head_re.match(full_str)
            assert m
            function_head_str = m.group()
            tail_str = full_str[len(function_head_str) :]
            arg_type_list, tail_str = cls.parse_type_list_str_with_tail(tail_str, type_separator_str)
            assert tail_str.startswith(function_mid_str)
            tail_str = tail_str[len(function_mid_str) :]
            ret_type_list, tail_str = cls.parse_type_list_str_with_tail(tail_str, type_separator_str)
            assert tail_str.startswith(type_end_str)
            tail_str = tail_str[len(type_end_str) :]
            return (
                function_head_str,
                arg_type_list,
                function_mid_str,
                ret_type_list,
                type_end_str,
            ), tail_str

    @classmethod
    def _recursive_join_inner(cls, parse_result):
        if isinstance(parse_result, str):
            return parse_result
        elif isinstance(parse_result, tuple):
            return "".join(map(cls._recursive_join_inner, parse_result))
        elif isinstance(parse_result, list):
            return type_separator_str.join(map(cls._recursive_join_inner, parse_result))

    @classmethod
    def parse_result_to_str(cls, parse_result):
        assert isinstance(parse_result, tuple)
        return cls._recursive_join_inner(parse_result)

    @classmethod
    def parse_multi_type_str(cls, full_str: str) -> List[Tuple[Tuple, str]]:
        tail_str = full_str
        type_tuple_list = []
        while tail_str.startswith("t_"):
            tmp_tuple, tail_str = TypeParser.parse_type_str_with_tail(tail_str)
            if tail_str.startswith("_"):
                tail_str = tail_str[1:]
            type_tuple_list.append(tmp_tuple)
        return type_tuple_list, tail_str

    @classmethod
    def get_type_str_by_index(index, type_str_with_tail):
        type_tuple_list, tail_str = TypeParser.parse_multi_type_str(type_str_with_tail)
        type_tuple = type_tuple_list[index]
        type_str = TypeParser.parse_result_to_str(type_tuple)
        return type_str
