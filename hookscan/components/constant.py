import json
from typing import Optional, Union

from hookscan.components.unique_id import IdGroup
from hookscan.components.value import User


class Constant(User):
    def __init__(self, id_group: IdGroup, value: Union[int, str], type_name: Optional[str] = None) -> None:
        super().__init__(id_group)
        self.value = value
        self.type_name = type_name

    def info_rvalue(self):
        return json.dumps(self.value)

    def __repr__(self):
        return self.info_rvalue()


class ConstantInt(Constant):
    pass


class ConstantStr(Constant):
    pass


class ConstantHexStr(Constant):
    pass


class ConstantBool(Constant):
    pass
