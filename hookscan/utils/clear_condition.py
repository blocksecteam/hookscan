from typing import Tuple

from hookscan.components.constant import ConstantInt
from hookscan.components.evm_instructions import Eq, Gt, Iszero, Lt, Sgt, Slt
from hookscan.core.instruction_instance import ValueInstance


def clear_condition(condition: ValueInstance) -> Tuple[int, ValueInstance]:
    temp_condition = condition
    is_zero_number = 0
    while isinstance(temp_condition.origin.value, (Iszero, Eq)):
        if isinstance(temp_condition.origin.value, Iszero):
            temp_condition = temp_condition.origin.operand_instances[0]
            is_zero_number += 1
        elif isinstance(temp_condition.origin.value, Eq):
            for index_operand in (0, 1):
                if isinstance(
                    temp_condition.origin.operand_instances[index_operand].origin.value,
                    ConstantInt,
                ) and isinstance(
                    temp_condition.origin.operand_instances[1 - index_operand].origin.value,
                    (Slt, Lt, Sgt, Gt, Eq, Iszero),
                ):
                    if temp_condition.origin.operand_instances[index_operand].origin.value.value == 1:
                        temp_condition = temp_condition.origin.operand_instances[1 - index_operand].origin
                        break
                    elif temp_condition.origin.operand_instances[index_operand].origin.value.value == 0:
                        temp_condition = temp_condition.origin.operand_instances[1 - index_operand].origin
                        is_zero_number += 1
                        break
            else:
                return is_zero_number, temp_condition.origin
    return is_zero_number, temp_condition.origin
