from uniscan.components.instruction import AbstractYulInst


class Setimmutable(AbstractYulInst):
    name: str = "setimmutable"


class Dataoffset(AbstractYulInst):
    name: str = "dataoffset"


class Datasize(AbstractYulInst):
    name: str = "datasize"


class Loadimmutable(AbstractYulInst):
    name: str = "loadimmutable"


class Linkersymbol(AbstractYulInst):
    name: str = "linkersymbol"


class Datacopy(AbstractYulInst):
    name: str = "datacopy"


class Memoryguard(AbstractYulInst):
    name: str = "memoryguard"


all_yul_instructions = [
    Setimmutable,
    Dataoffset,
    Datasize,
    Loadimmutable,
    Linkersymbol,
    Datacopy,
    Memoryguard,
]

all_yul_instructions_dict = {yul_inst.name: yul_inst for yul_inst in all_yul_instructions}
