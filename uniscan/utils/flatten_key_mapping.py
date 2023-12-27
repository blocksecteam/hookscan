from typing import TYPE_CHECKING, Tuple, Type, Union

from uniscan.components.constant import Constant, ConstantInt
from uniscan.components.evm_instructions import (
    AbstractEVMInst,
    Address,
    Blockhash,
    Calldatasize,
    Caller,
    Callvalue,
    Chainid,
    Codesize,
    Coinbase,
    Gaslimit,
    Gasprice,
    Number,
    Origin,
    Prevrandao,
    Timestamp,
)
from uniscan.components.yul_instructions import Loadimmutable

if TYPE_CHECKING:
    from uniscan.core.instruction_instance import ValueInstance

_key_list = [
    Blockhash,
    Caller,
    Callvalue,
    Chainid,
    Number,
    Origin,
    Timestamp,
    Address,
    Calldatasize,
    Codesize,
    Gasprice,
    Coinbase,
    Prevrandao,
    Gaslimit,
]

KEY_MAPPING = {item: item for item in _key_list}


def get_key(
    instance: "ValueInstance", need_convert: bool = True, in_storage: bool = False
) -> Union["ValueInstance", int, Type[AbstractEVMInst], Tuple, str]:
    if not need_convert:
        return instance

    instance = instance.origin
    inst = instance.value
    inst_cls = type(inst)
    if inst_cls in KEY_MAPPING:
        return KEY_MAPPING[inst_cls]
    elif issubclass(inst_cls, Loadimmutable):
        return (Loadimmutable, inst.operands[0].value)
    elif isinstance(inst, Constant):
        assert isinstance(inst, ConstantInt)
        if in_storage:
            return str(inst.value)
        else:
            return inst.value
    else:
        return instance.origin
