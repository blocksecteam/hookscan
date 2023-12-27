from uniscan.components.instruction import AbstractEVMInst


class Stop(AbstractEVMInst):
    name: str = "stop"
    n_args: int = 0
    n_rets: int = 0
    is_halt_inst: bool = True


class Add(AbstractEVMInst):
    name: str = "add"
    n_args: int = 2
    n_rets: int = 1
    is_halt_inst: bool = False


class Mul(AbstractEVMInst):
    name: str = "mul"
    n_args: int = 2
    n_rets: int = 1
    is_halt_inst: bool = False


class Sub(AbstractEVMInst):
    name: str = "sub"
    n_args: int = 2
    n_rets: int = 1
    is_halt_inst: bool = False


class Div(AbstractEVMInst):
    name: str = "div"
    n_args: int = 2
    n_rets: int = 1
    is_halt_inst: bool = False


class Sdiv(AbstractEVMInst):
    name: str = "sdiv"
    n_args: int = 2
    n_rets: int = 1
    is_halt_inst: bool = False


class Mod(AbstractEVMInst):
    name: str = "mod"
    n_args: int = 2
    n_rets: int = 1
    is_halt_inst: bool = False


class Smod(AbstractEVMInst):
    name: str = "smod"
    n_args: int = 2
    n_rets: int = 1
    is_halt_inst: bool = False


class Addmod(AbstractEVMInst):
    name: str = "addmod"
    n_args: int = 3
    n_rets: int = 1
    is_halt_inst: bool = False


class Mulmod(AbstractEVMInst):
    name: str = "mulmod"
    n_args: int = 3
    n_rets: int = 1
    is_halt_inst: bool = False


class Exp(AbstractEVMInst):
    name: str = "exp"
    n_args: int = 2
    n_rets: int = 1
    is_halt_inst: bool = False


class Signextend(AbstractEVMInst):
    name: str = "signextend"
    n_args: int = 2
    n_rets: int = 1
    is_halt_inst: bool = False


class Lt(AbstractEVMInst):
    name: str = "lt"
    n_args: int = 2
    n_rets: int = 1
    is_halt_inst: bool = False


class Gt(AbstractEVMInst):
    name: str = "gt"
    n_args: int = 2
    n_rets: int = 1
    is_halt_inst: bool = False


class Slt(AbstractEVMInst):
    name: str = "slt"
    n_args: int = 2
    n_rets: int = 1
    is_halt_inst: bool = False


class Sgt(AbstractEVMInst):
    name: str = "sgt"
    n_args: int = 2
    n_rets: int = 1
    is_halt_inst: bool = False


class Eq(AbstractEVMInst):
    name: str = "eq"
    n_args: int = 2
    n_rets: int = 1
    is_halt_inst: bool = False


class Iszero(AbstractEVMInst):
    name: str = "iszero"
    n_args: int = 1
    n_rets: int = 1
    is_halt_inst: bool = False


class And(AbstractEVMInst):
    name: str = "and"
    n_args: int = 2
    n_rets: int = 1
    is_halt_inst: bool = False


class Or(AbstractEVMInst):
    name: str = "or"
    n_args: int = 2
    n_rets: int = 1
    is_halt_inst: bool = False


class Xor(AbstractEVMInst):
    name: str = "xor"
    n_args: int = 2
    n_rets: int = 1
    is_halt_inst: bool = False


class Not(AbstractEVMInst):
    name: str = "not"
    n_args: int = 1
    n_rets: int = 1
    is_halt_inst: bool = False


class Byte(AbstractEVMInst):
    name: str = "byte"
    n_args: int = 2
    n_rets: int = 1
    is_halt_inst: bool = False


class Shl(AbstractEVMInst):
    name: str = "shl"
    n_args: int = 2
    n_rets: int = 1
    is_halt_inst: bool = False


class Shr(AbstractEVMInst):
    name: str = "shr"
    n_args: int = 2
    n_rets: int = 1
    is_halt_inst: bool = False


class Sar(AbstractEVMInst):
    name: str = "sar"
    n_args: int = 2
    n_rets: int = 1
    is_halt_inst: bool = False


class Keccak256(AbstractEVMInst):
    name: str = "keccak256"
    n_args: int = 2
    n_rets: int = 1
    is_halt_inst: bool = False


class Address(AbstractEVMInst):
    name: str = "address"
    n_args: int = 0
    n_rets: int = 1
    is_halt_inst: bool = False


class Balance(AbstractEVMInst):
    name: str = "balance"
    n_args: int = 1
    n_rets: int = 1
    is_halt_inst: bool = False


class Origin(AbstractEVMInst):
    name: str = "origin"
    n_args: int = 0
    n_rets: int = 1
    is_halt_inst: bool = False


class Caller(AbstractEVMInst):
    name: str = "caller"
    n_args: int = 0
    n_rets: int = 1
    is_halt_inst: bool = False


class Callvalue(AbstractEVMInst):
    name: str = "callvalue"
    n_args: int = 0
    n_rets: int = 1
    is_halt_inst: bool = False


class Calldataload(AbstractEVMInst):
    name: str = "calldataload"
    n_args: int = 1
    n_rets: int = 1
    is_halt_inst: bool = False


class Calldatasize(AbstractEVMInst):
    name: str = "calldatasize"
    n_args: int = 0
    n_rets: int = 1
    is_halt_inst: bool = False


class Calldatacopy(AbstractEVMInst):
    name: str = "calldatacopy"
    n_args: int = 3
    n_rets: int = 0
    is_halt_inst: bool = False


class Codesize(AbstractEVMInst):
    name: str = "codesize"
    n_args: int = 0
    n_rets: int = 1
    is_halt_inst: bool = False


class Codecopy(AbstractEVMInst):
    name: str = "codecopy"
    n_args: int = 3
    n_rets: int = 0
    is_halt_inst: bool = False


class Gasprice(AbstractEVMInst):
    name: str = "gasprice"
    n_args: int = 0
    n_rets: int = 1
    is_halt_inst: bool = False


class Extcodesize(AbstractEVMInst):
    name: str = "extcodesize"
    n_args: int = 1
    n_rets: int = 1
    is_halt_inst: bool = False


class Extcodecopy(AbstractEVMInst):
    name: str = "extcodecopy"
    n_args: int = 4
    n_rets: int = 0
    is_halt_inst: bool = False


class Returndatasize(AbstractEVMInst):
    name: str = "returndatasize"
    n_args: int = 0
    n_rets: int = 1
    is_halt_inst: bool = False


class Returndatacopy(AbstractEVMInst):
    name: str = "returndatacopy"
    n_args: int = 3
    n_rets: int = 0
    is_halt_inst: bool = False


class Extcodehash(AbstractEVMInst):
    name: str = "extcodehash"
    n_args: int = 1
    n_rets: int = 1
    is_halt_inst: bool = False


class Blockhash(AbstractEVMInst):
    name: str = "blockhash"
    n_args: int = 1
    n_rets: int = 1
    is_halt_inst: bool = False


class Coinbase(AbstractEVMInst):
    name: str = "coinbase"
    n_args: int = 0
    n_rets: int = 1
    is_halt_inst: bool = False


class Timestamp(AbstractEVMInst):
    name: str = "timestamp"
    n_args: int = 0
    n_rets: int = 1
    is_halt_inst: bool = False


class Number(AbstractEVMInst):
    name: str = "number"
    n_args: int = 0
    n_rets: int = 1
    is_halt_inst: bool = False


class Prevrandao(AbstractEVMInst):
    name: str = "prevrandao"
    n_args: int = 0
    n_rets: int = 1
    is_halt_inst: bool = False


class Gaslimit(AbstractEVMInst):
    name: str = "gaslimit"
    n_args: int = 0
    n_rets: int = 1
    is_halt_inst: bool = False


class Chainid(AbstractEVMInst):
    name: str = "chainid"
    n_args: int = 0
    n_rets: int = 1
    is_halt_inst: bool = False


class Selfbalance(AbstractEVMInst):
    name: str = "selfbalance"
    n_args: int = 0
    n_rets: int = 1
    is_halt_inst: bool = False


class Basefee(AbstractEVMInst):
    name: str = "basefee"
    n_args: int = 0
    n_rets: int = 1
    is_halt_inst: bool = False


class Pop(AbstractEVMInst):
    name: str = "pop"
    n_args: int = 1
    n_rets: int = 0
    is_halt_inst: bool = False


class Mload(AbstractEVMInst):
    name: str = "mload"
    n_args: int = 1
    n_rets: int = 1
    is_halt_inst: bool = False


class Mstore(AbstractEVMInst):
    name: str = "mstore"
    n_args: int = 2
    n_rets: int = 0
    is_halt_inst: bool = False


class Mstore8(AbstractEVMInst):
    name: str = "mstore8"
    n_args: int = 2
    n_rets: int = 0
    is_halt_inst: bool = False


class Sload(AbstractEVMInst):
    name: str = "sload"
    n_args: int = 1
    n_rets: int = 1
    is_halt_inst: bool = False


class Sstore(AbstractEVMInst):
    name: str = "sstore"
    n_args: int = 2
    n_rets: int = 0
    is_halt_inst: bool = False


class Pc(AbstractEVMInst):
    name: str = "pc"
    n_args: int = 0
    n_rets: int = 1
    is_halt_inst: bool = False


class Msize(AbstractEVMInst):
    name: str = "msize"
    n_args: int = 0
    n_rets: int = 1
    is_halt_inst: bool = False


class Gas(AbstractEVMInst):
    name: str = "gas"
    n_args: int = 0
    n_rets: int = 1
    is_halt_inst: bool = False


class Log0(AbstractEVMInst):
    name: str = "log0"
    n_args: int = 2
    n_rets: int = 0
    is_halt_inst: bool = False


class Log1(AbstractEVMInst):
    name: str = "log1"
    n_args: int = 3
    n_rets: int = 0
    is_halt_inst: bool = False


class Log2(AbstractEVMInst):
    name: str = "log2"
    n_args: int = 4
    n_rets: int = 0
    is_halt_inst: bool = False


class Log3(AbstractEVMInst):
    name: str = "log3"
    n_args: int = 5
    n_rets: int = 0
    is_halt_inst: bool = False


class Log4(AbstractEVMInst):
    name: str = "log4"
    n_args: int = 6
    n_rets: int = 0
    is_halt_inst: bool = False


class Create(AbstractEVMInst):
    name: str = "create"
    n_args: int = 3
    n_rets: int = 1
    is_halt_inst: bool = False


class Call(AbstractEVMInst):
    name: str = "call"
    n_args: int = 7
    n_rets: int = 1
    is_halt_inst: bool = False


class Callcode(AbstractEVMInst):
    name: str = "callcode"
    n_args: int = 7
    n_rets: int = 1
    is_halt_inst: bool = False


class Return(AbstractEVMInst):
    name: str = "return"
    n_args: int = 2
    n_rets: int = 0
    is_halt_inst: bool = True


class Delegatecall(AbstractEVMInst):
    name: str = "delegatecall"
    n_args: int = 6
    n_rets: int = 1
    is_halt_inst: bool = False


class Create2(AbstractEVMInst):
    name: str = "create2"
    n_args: int = 4
    n_rets: int = 1
    is_halt_inst: bool = False


class Staticcall(AbstractEVMInst):
    name: str = "staticcall"
    n_args: int = 6
    n_rets: int = 1
    is_halt_inst: bool = False


class Revert(AbstractEVMInst):
    name: str = "revert"
    n_args: int = 2
    n_rets: int = 0
    is_halt_inst: bool = True


class Invalid(AbstractEVMInst):
    name: str = "invalid"
    n_args: int = 0
    n_rets: int = 0
    is_halt_inst: bool = True


class Selfdestruct(AbstractEVMInst):
    name: str = "selfdestruct"
    n_args: int = 1
    n_rets: int = 0
    is_halt_inst: bool = True


all_evm_instructions = [
    Stop,
    Add,
    Mul,
    Sub,
    Div,
    Sdiv,
    Mod,
    Smod,
    Addmod,
    Mulmod,
    Exp,
    Signextend,
    Lt,
    Gt,
    Slt,
    Sgt,
    Eq,
    Iszero,
    And,
    Or,
    Xor,
    Not,
    Byte,
    Shl,
    Shr,
    Sar,
    Keccak256,
    Address,
    Balance,
    Origin,
    Caller,
    Callvalue,
    Calldataload,
    Calldatasize,
    Calldatacopy,
    Codesize,
    Codecopy,
    Gasprice,
    Extcodesize,
    Extcodecopy,
    Returndatasize,
    Returndatacopy,
    Extcodehash,
    Blockhash,
    Coinbase,
    Timestamp,
    Number,
    Prevrandao,
    Gaslimit,
    Chainid,
    Selfbalance,
    Basefee,
    Pop,
    Mload,
    Mstore,
    Mstore8,
    Sload,
    Sstore,
    Pc,
    Msize,
    Gas,
    Log0,
    Log1,
    Log2,
    Log3,
    Log4,
    Create,
    Call,
    Callcode,
    Return,
    Delegatecall,
    Create2,
    Staticcall,
    Revert,
    Invalid,
    Selfdestruct,
]

all_evm_instructions_dict = {evm_inst.name: evm_inst for evm_inst in all_evm_instructions}

# NOTE DIFFICULTY renames to PREVRANDAO
all_evm_instructions_dict["difficulty"] = Prevrandao
