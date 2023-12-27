from contextlib import suppress
from typing import Any, Dict, List, Union

from uniscan.components.evm_instructions import (
    Call,
    Callcode,
    Calldatasize,
    Delegatecall,
    Log0,
    Log1,
    Log2,
    Log3,
    Log4,
    Selfdestruct,
)
from uniscan.components.function import Function, FunctionType
from uniscan.components.instruction import BranchInst, CallInst
from uniscan.components.storage_instructions import StorageUpdateInst
from uniscan.components.unique_id import IdGroup, UniqueId
from uniscan.utils.ordered_set import OrderedSet as set
from uniscan.utils.transform import replace_builtin_functions


class Contract(UniqueId):
    def __init__(self) -> None:
        super().__init__(IdGroup())
        self.file_name: str
        self.contract_name: str
        self.yul_name: str
        self.file_name_map: Dict[str, str]
        self.source_code_map: Dict[str, Any]
        self.std_in_json: Union[Dict[str, Any], None]
        self.std_out_json: Dict[str, Any]

        self.creation: Function
        self.creation_functions_dict: Dict[str, Function] = {}
        self.runtime: Function
        self.runtime_functions_dict: Dict[str, Function] = {}
        self.dispatcher: Dict[int, Function]
        self._all_functions: List[Function]

        self.other_created_contract_names: List[str] = []

        self.yul_list_by_line: List[str]
        self.yul: str

    def info(self):
        creation = [x.info() for x in [self.creation] + list(self.creation_functions_dict.values())]
        runtime = [x.info() for x in [self.runtime] + list(self.runtime_functions_dict.values())]
        return {
            "contract_name": self.yul_name,
            "creation_functions": creation,
            "runtime_functions": runtime,
        }

    def initialize(
        self,
        yul: str,
        std_in_json,
        std_out_json,
        file_name,
        contract_name,
    ):
        self.yul = yul
        self.yul_list_by_line = yul.splitlines()
        self.std_in_json = std_in_json
        self.std_out_json = std_out_json
        self.initialize_source_code_map()
        self.initialize_file_name_map()
        self.file_name = file_name
        self.contract_name = contract_name
        self.transform()
        self.generate_mutability_info()

    def initialize_file_name_map(self):
        self.file_name_map = {}
        for filename, file_info in self.std_out_json["sources"].items():
            self.file_name_map[str(file_info["id"])] = filename

    def initialize_source_code_map(self):
        self.source_code_map = {}
        if self.std_in_json is None:
            return
        for filename, file_info in self.std_in_json["sources"].items():
            self.source_code_map[filename] = file_info

    @property
    def all_functions(self) -> List[Function]:
        try:
            return self._all_functions
        except AttributeError:
            self._all_functions = []
            self._all_functions.append(self.creation)
            self._all_functions.extend(self.creation_functions_dict.values())
            self._all_functions.append(self.runtime)
            self._all_functions.extend(self.runtime_functions_dict.values())
            return self._all_functions

    def _refresh_all_functions(self):
        with suppress(AttributeError):
            del self._all_functions

    def transform(self):
        replace_builtin_functions(self)
        self.verify()

    def verify(self):
        for function in self.all_functions:
            for bb in function.basic_blocks:
                for inst in bb.instructions:
                    for o in inst.operands:
                        assert inst in o.users
                    for u in inst.users:
                        assert inst in u.operands

    def identify_payable(self):
        for function in self.all_functions:
            if function.type == FunctionType.EXTERNAL:
                first_inst = function.entry_point.instructions[0]
                if isinstance(first_inst, Calldatasize):
                    function.mutability_info._payable = True
                elif isinstance(first_inst, BranchInst):
                    function.mutability_info._payable = False
                else:
                    raise Exception("payable identify meet unknown pattern")
            elif function.type == FunctionType.FALLBACK:
                assert function.users.__len__() == 1
                call_bb = function.users[0].basic_block  # pyright: ignore
                if call_bb.predecessors.__len__() == 0:
                    function.mutability_info._payable = True
                    return

                def is_receive(call_bb):
                    inner_predecessor = call_bb.predecessors[0]
                    if isinstance(inner_predecessor.instructions[0], Calldatasize):
                        return True
                    return False

                if is_receive(call_bb):
                    function.mutability_info._payable = True
                else:
                    predecessor = call_bb.predecessors[0]
                    if isinstance(predecessor.instructions[0], BranchInst) and predecessor.users.__len__() == 2:
                        user1_block = predecessor.users[0].basic_block
                        user2_block = predecessor.users[1].basic_block
                        if user1_block in user2_block.predecessors or user2_block in user1_block.predecessors:
                            function.mutability_info._payable = False
                        else:
                            function.mutability_info._payable = True
                    else:
                        function.mutability_info._payable = True

    def _generate_mutability_info_dfs(self, func: Function, visited_funcs: set):
        if func in visited_funcs:
            return
        visited_funcs.add(func)
        for bb in func.basic_blocks:
            for inst in bb.instructions:
                if isinstance(inst, (Call, Delegatecall, Callcode)):
                    func.mutability_info.non_static_call = True
                elif isinstance(inst, StorageUpdateInst):
                    func.mutability_info.storage_write = True
                elif isinstance(inst, (Log0, Log1, Log2, Log3, Log4)):
                    func.mutability_info.log = True
                elif isinstance(inst, Selfdestruct):
                    func.mutability_info.self_destruct = True
                elif isinstance(inst, CallInst):
                    self._generate_mutability_info_dfs(inst.called_function, visited_funcs)
                    func.mutability_info.update(inst.called_function.mutability_info)

    def generate_mutability_info(self):
        self.identify_payable()
        visited_funcs = set()
        for func in self.all_functions:
            self._generate_mutability_info_dfs(func, visited_funcs)
