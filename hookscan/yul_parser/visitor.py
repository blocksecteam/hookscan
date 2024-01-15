import ast
import contextlib
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, MutableSet, Optional, Tuple

from antlr4 import ParserRuleContext, TerminalNode

from hookscan.components.basic_block import BasicBlock
from hookscan.components.constant import Constant, ConstantBool, ConstantHexStr, ConstantInt, ConstantStr
from hookscan.components.contract import Contract
from hookscan.components.evm_instructions import And, Eq, Gt, Iszero, Lt, Sgt, Slt, all_evm_instructions_dict
from hookscan.components.function import Function, FunctionType
from hookscan.components.instruction import (
    AbstractEVMInst,
    BranchInst,
    CallInst,
    ExtractReturnValue,
    Instruction,
    PHINode,
    ReturnInst,
    SwitchInst,
    UnreachableInst,
)
from hookscan.components.value import Argument, Value
from hookscan.components.yul_instructions import all_yul_instructions_dict
from hookscan.utils.ordered_set import OrderedSet as set
from hookscan.yul_parser.antlr.YulParser import YulParser


@dataclass
class Variable:
    name: str
    curr_value: Optional[Value]


class VariableTable:
    def __init__(self) -> None:
        self._data: List[Dict[str, Variable]] = []

    def append_scope(self):
        self._data.append({})

    def pop_scope(self):
        self._data.pop()

    def set_variable(self, name, value):
        for scope in reversed(self._data):
            if name in scope:
                scope[name].curr_value = value
                break
        else:
            raise KeyError(f"variable {name} not find")

    def add_variable(self, name, value=None):
        assert all(name not in v for v in self._data)
        curr_scope = self._data[-1]
        assert name not in curr_scope
        variable = Variable(name=name, curr_value=value)
        curr_scope[name] = variable

    def get_variable_value(self, name, i=None):
        if i is not None:
            return self._data[i][name].curr_value
        for scope in reversed(self._data):
            if name in scope:
                value = scope[name].curr_value
                assert value is not None
                return value
        else:
            raise KeyError(f"variable {name} not find")

    def copy(self):
        vt = VariableTable()
        vt._data = [{k: Variable(k, v.curr_value) for k, v in d.items()} for d in self._data]
        return vt


@dataclass
class BlockReturnData:
    entry_point: Optional[BasicBlock] = None
    exit_point: Optional[BasicBlock] = None
    continue_bbs: List[Tuple[BasicBlock, VariableTable]] = field(default_factory=list)
    break_bbs: List[Tuple[BasicBlock, VariableTable]] = field(default_factory=list)
    leave_bbs: List[Tuple[BasicBlock, VariableTable]] = field(default_factory=list)


class Visitor:
    def __init__(self) -> None:
        self.contract: Contract
        self.for_init_blocks: MutableSet[BasicBlock] = set()
        _key_type = YulParser.ForLoopContext
        _value_type = MutableSet[str]
        self.for2assignment_name: defaultdict[_key_type, _value_type] = defaultdict(set)
        self.func_id2ctx: Dict[int, YulParser.FunctionDefinitionContext] = {}
        self.start_func_id: MutableSet[int] = set()
        self.end_func_id: MutableSet[int] = set()

    def _get_source_map(self, ctx: ParserRuleContext):
        return (
            ctx.start.line,  # pyright: ignore
            ctx.start.column,  # pyright: ignore
            ctx.stop.line,  # pyright: ignore
            ctx.stop.column,  # pyright: ignore
        )

    def _get_declared_functions_dict(self, is_runtime):
        if is_runtime:
            functions_dict = self.contract.runtime_functions_dict
        else:
            functions_dict = self.contract.creation_functions_dict
        return functions_dict

    def _get_func(self, func_name, is_runtime) -> Function:
        assert func_name
        functions_dict = self._get_declared_functions_dict(is_runtime)
        return functions_dict[func_name]

    def _handle_func_declaration(self, block_ctx, is_runtime) -> None:
        functions = self._get_declared_functions_dict(is_runtime)

        assert len(block_ctx.children) >= 2
        for stmt in block_ctx.children[1:-1]:
            child = stmt.children[0]
            if not isinstance(child, YulParser.FunctionDefinitionContext):
                continue
            func = self.visit(child, is_runtime=is_runtime, only_declare=True)
            assert func is not None
            assert func.name not in all_evm_instructions_dict
            assert func.name not in functions
            functions[func.name] = func

    def _infer_func_type(self, name: str, ctx: YulParser.FunctionDefinitionContext):
        if name.startswith("constructor_"):
            return FunctionType.CONSTRUCTOR
        elif name.startswith("external_fun_"):
            return FunctionType.EXTERNAL
        elif name.startswith("getter_fun_"):
            return FunctionType.GETTER
        elif name.startswith("modifier_"):
            return FunctionType.MODIFIER
        elif re.match(r"fun__\d+", name) and not name.endswith("inner"):
            return FunctionType.FALLBACK
        elif name.startswith("fun_") or name.startswith("usr$"):
            return FunctionType.INTERNAL
        elif name.startswith("constant_"):
            return FunctionType.CONSTANT
        else:
            return FunctionType.YUL_FUNCTION

    def _handle_func_ret(self, func, leave_bbs):
        for bb, vt in leave_bbs:
            assert bb.terminator is None
            values = [vt.get_variable_value(name) for name in func.return_names]
            ret = ReturnInst(values=values, basic_block=bb)
            func.return_instructions.append(ret)
        return

    def _extract_values(self, exp, curr_bb) -> List[Value]:
        if not isinstance(exp, CallInst):
            return [exp]
        return_count = exp.called_function.return_count
        return [
            ExtractReturnValue(exp, i, return_count, basic_block=curr_bb, yul_source_map=exp.yul_source_map)
            for i in range(return_count)
        ]

    def _generate_phi(self, predecessors, variable_tables, target_variable_table, curr_bb):
        assert len(predecessors) == len(variable_tables)
        assert len(predecessors) > 0
        for i, scope in enumerate(target_variable_table._data):
            for name, variable in scope.items():
                value = variable.curr_value
                diff = False
                for vt in variable_tables:
                    new_value = vt.get_variable_value(name, i)
                    assert new_value is not None
                    if new_value.id != value.id:
                        diff = True
                        break
                if diff:
                    values = [vt.get_variable_value(name, i) for vt in variable_tables]
                    if len(values) == 1:
                        # not generate phi
                        variable.curr_value = values[0]
                    else:
                        phi = PHINode(predecessors, values, basic_block=curr_bb)
                        variable.curr_value = phi

    def _collect_for_assignments(self, ctx, for_list=None):
        if for_list is None:
            for_list = []
        if isinstance(ctx, TerminalNode):
            return
        elif isinstance(ctx, YulParser.ForLoopContext):
            _, init, _, tail, body = ctx.children  # pyright: ignore
            self._collect_for_assignments(init, for_list)
            for_list.append(ctx)
            self._collect_for_assignments(body, for_list)
            self._collect_for_assignments(tail, for_list)
            for_list.pop()
        elif isinstance(ctx, YulParser.AssignmentContext):
            for for_ctx in for_list:
                id_list_cxt = ctx.children[0]  # pyright: ignore
                assert isinstance(id_list_cxt, YulParser.IdentifierListContext)
                for name in self.visit(id_list_cxt):
                    self.for2assignment_name[for_ctx].add(name)
        else:
            for child in ctx.children:
                self._collect_for_assignments(child, for_list)

    def _remove_phi(self, phi: PHINode):
        real_value = phi.values[0]
        real_value.users.extend(phi.users)
        for user in phi.users:
            for i, value in enumerate(user.operands):
                if value.id == phi.id:
                    user.operands[i] = real_value
        phi.basic_block.instructions.remove(phi)
        for i, inst in enumerate(phi.basic_block.instructions):
            inst.bb_index = i

    def _phi_pass(self):
        for func in self.contract.all_functions:
            for bb in func.basic_blocks:
                for inst in bb.instructions:
                    if not isinstance(inst, PHINode):
                        break
                    real_value = inst.values[0]
                    assert len(inst.values) >= 1
                    real_value = inst.values[0]
                    assert real_value.id != inst.id
                    if all(v.id == real_value.id for v in inst.values):
                        self._remove_phi(inst)

    def _is_bool(self, condition: Value):
        if not isinstance(condition, AbstractEVMInst):
            return False

        if isinstance(condition, (Lt, Gt, Slt, Sgt, Eq, Iszero)):
            return True

        if isinstance(condition, And):
            v1 = condition.arguments[1]
            if not isinstance(v1, ConstantInt):
                return False
            return v1.value == 1

        return False

    def _get_external_func_from_dispatcher(self, bb: BasicBlock) -> Function:
        term = bb.terminator
        assert isinstance(term, BranchInst)
        if len(bb.instructions) == 1:
            assert not term.is_conditional
            return self._get_external_func_from_dispatcher(term.get_successor(when=None))

        if term.is_conditional:
            raise NotImplementedError("the contract type is library")

        assert len(bb.instructions) == 2
        _inst = bb.instructions[0]
        assert isinstance(_inst, CallInst)
        _func = _inst.called_function
        assert _func.type == FunctionType.EXTERNAL
        return _func

    def visit(self, ctx: ParserRuleContext, **kwargs):
        class_name = type(ctx).__name__
        func_name = f"visit{class_name[:-7]}"
        return getattr(self, func_name)(ctx, **kwargs)

    def visitProg(self, ctx: YulParser.ProgContext) -> Contract:
        self.contract = Contract()

        assert len(ctx.children) == 1  # pyright: ignore
        obj_ctx = ctx.children[0]  # pyright: ignore
        assert isinstance(obj_ctx, YulParser.ObjectContext)
        self.visit(obj_ctx)

        self._phi_pass()

        self.contract.verify()

        return self.contract

    def visitObject(self, ctx: YulParser.ObjectContext) -> None:
        if isinstance(ctx.parentCtx, YulParser.ProgContext):
            assert len(ctx.children) >= 6  # pyright: ignore
            code_ctx = ctx.children[3]  # pyright: ignore
            assert isinstance(code_ctx, YulParser.CodeContext)
            self.contract.yul_name = self.visit(ctx.children[1]).value  # pyright: ignore
            self.visit(code_ctx, is_runtime=False, last_loop_entry=None)

            obj_ctx = ctx.children[4]  # pyright: ignore
            assert isinstance(obj_ctx, YulParser.ObjectContext)
            self.visit(obj_ctx)

            for i in range(5, len(ctx.children) - 1):  # pyright: ignore
                obj_ctx = ctx.children[i]  # pyright: ignore
                assert isinstance(obj_ctx, YulParser.ObjectContext)
                self.visit(obj_ctx)
        else:
            assert isinstance(ctx.parentCtx, YulParser.ObjectContext)
            name = self.visit(ctx.children[1]).value  # pyright: ignore
            if name == self.contract.yul_name + "_deployed":
                assert len(ctx.children) >= 5  # pyright: ignore
                code_ctx = ctx.children[3]  # pyright: ignore
                assert isinstance(code_ctx, YulParser.CodeContext)
                self.visit(code_ctx, is_runtime=True, last_loop_entry=None)
            else:
                assert name[-9:] != "_deployed"
                self.contract.other_created_contract_names.append(name)

    def visitCode(self, ctx: YulParser.CodeContext, **kwargs) -> None:
        self._collect_for_assignments(ctx)

        assert len(ctx.children) == 2  # pyright: ignore
        block_ctx = ctx.children[1]  # pyright: ignore
        assert isinstance(block_ctx, YulParser.BlockContext)
        self._handle_func_declaration(block_ctx, kwargs["is_runtime"])

        main_func = Function(self.contract)
        main_func.yul_source_map = self._get_source_map(ctx)
        main_func.is_runtime = kwargs["is_runtime"]
        if kwargs["is_runtime"]:
            main_func.name = "__runtime"
            main_func.type = FunctionType.RUNTIME
            self.contract.runtime = main_func
        else:
            main_func.name = "__creation"
            main_func.type = FunctionType.CREATION
            self.contract.creation = main_func

        kwargs["curr_func"] = main_func
        kwargs["variable_table"] = VariableTable()
        block_data = self.visit(block_ctx, **kwargs)

        assert block_data.entry_point is not None
        main_func.entry_point = block_data.entry_point
        assert not block_data.leave_bbs
        assert not block_data.break_bbs
        assert not block_data.continue_bbs

        functions = self._get_declared_functions_dict(kwargs["is_runtime"])
        assert self.start_func_id == self.end_func_id
        to_remove_name = []
        for name, func in functions.items():
            if func.id not in self.start_func_id:
                to_remove_name.append(name)
        for name in to_remove_name:
            del functions[name]

    def visitData(self, ctx: YulParser.DataContext, **kwargs):
        raise NotImplementedError

    def visitBlock(self, ctx: YulParser.BlockContext, **kwargs) -> BlockReturnData:
        # append scope
        if ctx not in self.for_init_blocks:
            kwargs["variable_table"].append_scope()

        # return entry, exit
        curr_bb = BasicBlock(function=kwargs["curr_func"], last_loop_entry=kwargs["last_loop_entry"])
        block_data = BlockReturnData(
            entry_point=curr_bb,
            exit_point=None,
            continue_bbs=[],
            break_bbs=[],
            leave_bbs=[],
        )
        with contextlib.suppress(KeyError):
            del kwargs["curr_bb"]

        assert len(ctx.children) >= 2  # pyright: ignore
        statements = ctx.children[1:-1]  # pyright: ignore
        for statement in statements:
            if curr_bb is None:
                kwargs["curr_func"].has_dead_code = True
                break
            assert len(statement.children) == 1
            child = statement.children[0]
            inst_type = (
                YulParser.VariableDeclarationContext,
                YulParser.AssignmentContext,
                YulParser.ExpressionContext,
            )
            block_type = (
                YulParser.BlockContext,
                YulParser.IfContext,
                YulParser.SwitchContext,
                YulParser.ForLoopContext,
            )
            if isinstance(child, YulParser.FunctionDefinitionContext):
                if not isinstance(child.parentCtx.parentCtx.parentCtx, YulParser.CodeContext):
                    # Functions can be defined anywhere and are visible in the block they are declared in. Inside a function, you cannot access local variables defined outside of that function.
                    _func_dict = self._get_declared_functions_dict(kwargs["curr_func"].is_runtime)
                    _func = self.visit(child, only_declare=True, **kwargs)
                    assert _func.name not in _func_dict, f"duplicated definition of func {_func.name}"
                    _func_dict[_func.name] = _func
                    self.visit(child, only_declare=False, **kwargs)
                else:
                    # NOTE already done
                    # self.visit(child, handle_func_declaration=False, **kwargs)
                    pass
            elif isinstance(child, inst_type):
                self.visit(child, curr_bb=curr_bb, **kwargs)
                if curr_bb.terminator is not None:
                    curr_bb = None
            elif isinstance(child, block_type):
                child_data = self.visit(child, **kwargs)
                BranchInst(None, [child_data.entry_point], basic_block=curr_bb)
                if child_data.exit_point is not None:
                    curr_bb = BasicBlock(function=kwargs["curr_func"], last_loop_entry=kwargs["last_loop_entry"])
                    BranchInst(None, [curr_bb], child_data.exit_point)
                else:
                    curr_bb = None
                block_data.continue_bbs.extend(child_data.continue_bbs)
                block_data.break_bbs.extend(child_data.break_bbs)
                block_data.leave_bbs.extend(child_data.leave_bbs)
            elif isinstance(child, YulParser.BreakContinueContext):
                text = child.getText()
                if text == "break":
                    block_data.break_bbs.append((curr_bb, kwargs["variable_table"].copy()))
                else:
                    assert text == "continue"
                    block_data.continue_bbs.append((curr_bb, kwargs["variable_table"].copy()))
                curr_bb = None
            elif isinstance(child, YulParser.LeaveContext):
                block_data.leave_bbs.append((curr_bb, kwargs["variable_table"].copy()))
                curr_bb = None
            else:
                raise Exception(f"unknown statement type: {type(child).__name__}")

        if ctx not in self.for_init_blocks:
            kwargs["variable_table"].pop_scope()

        block_data.exit_point = curr_bb
        return block_data

    def visitStatement(self, ctx: YulParser.StatementContext, **kwargs):
        # deprecated
        raise NotImplementedError

    def visitFunctionDefinition(
        self, ctx: YulParser.FunctionDefinitionContext, only_declare=False, **kwargs
    ) -> Function:
        if only_declare:
            func = Function(self.contract)
            func.yul_source_map = self._get_source_map(ctx)
            self.func_id2ctx[func.id] = ctx
            func.is_runtime = kwargs["is_runtime"]
            func.name = ctx.children[1].getText()  # pyright: ignore
            func.type = self._infer_func_type(func.name, ctx)
            assert len(func.name) != 0
            assert func.name not in all_evm_instructions_dict

            kwargs["curr_func"] = func

            next_index = 3

            # arguments
            next_child = ctx.children[next_index]  # pyright: ignore
            if isinstance(next_child, YulParser.TypedIdentifierListContext):
                func.arguments = [
                    Argument(name=name, func=func, index=i) for i, name in enumerate(self.visit(next_child, **kwargs))
                ]
                next_index += 1
            else:
                func.arguments = []

            next_child = ctx.children[next_index]  # pyright: ignore
            assert isinstance(next_child, TerminalNode)
            if next_child.getText() == ",":  # pyright: ignore
                next_index += 1

            next_child = ctx.children[next_index]  # pyright: ignore
            assert isinstance(next_child, TerminalNode)
            assert next_child.getText() == ")"  # pyright: ignore
            next_index += 1

            # returns
            next_child = ctx.children[next_index]  # pyright: ignore
            if isinstance(next_child, YulParser.BlockContext):
                func.return_names = []
            else:
                assert isinstance(next_child, TerminalNode)
                assert next_child.getText() == "->"  # pyright: ignore
                return_ctx = ctx.children[next_index + 1]  # pyright: ignore
                func.return_names = self.visit(return_ctx, **kwargs)
                next_index += 2
            assert next_index == len(ctx.children) - 1  # pyright: ignore

        else:
            func_name = ctx.children[1].getText()  # pyright: ignore
            func = self._get_func(func_name, kwargs["is_runtime"])

            if func.id in self.start_func_id:
                return func
            else:
                self.start_func_id.add(func.id)

            # setup variable table
            vt = VariableTable()
            vt.append_scope()
            kwargs["variable_table"] = vt

            for arg in func.arguments:
                assert isinstance(arg, Value)
                vt.add_variable(name=arg.name, value=arg)
            for ret_name in func.return_names:
                vt.add_variable(name=ret_name, value=ConstantInt(self.contract.id_group, 0))

            # function body
            block_ctx = ctx.children[-1]  # pyright: ignore
            assert isinstance(block_ctx, YulParser.BlockContext)

            kwargs["curr_func"] = func
            kwargs["last_loop_entry"] = None
            block_data: BlockReturnData = self.visit(block_ctx, **kwargs)
            assert block_data.entry_point is not None
            func.entry_point = block_data.entry_point
            assert not block_data.break_bbs
            assert not block_data.continue_bbs

            leave_bbs = list(block_data.leave_bbs)
            if block_data.exit_point is not None:
                leave_bbs.append((block_data.exit_point, vt.copy()))
            self._handle_func_ret(func, leave_bbs)

            self.end_func_id.add(func.id)

        return func

    def visitVariableDeclaration(self, ctx: YulParser.VariableDeclarationContext, **kwargs):
        identifiers_ctx = ctx.children[1]  # pyright: ignore
        assert isinstance(identifiers_ctx, YulParser.TypedIdentifierListContext)
        identifiers = self.visit(identifiers_ctx, **kwargs)

        if len(ctx.children) == 4:  # pyright: ignore
            expression_ctx = ctx.children[3]  # pyright: ignore
            assert isinstance(expression_ctx, YulParser.ExpressionContext)
            values = self.visit(expression_ctx, **kwargs)
        else:
            values = [ConstantInt(self.contract.id_group, 0) for _ in range(len(identifiers))]

        for identifier, value in zip(identifiers, values):
            kwargs["variable_table"].add_variable(identifier, value)

    def visitAssignment(self, ctx: YulParser.AssignmentContext, **kwargs):
        identifiers_ctx, _, expression_ctx = ctx.children  # pyright: ignore
        identifiers = self.visit(identifiers_ctx, **kwargs)
        values = self.visit(expression_ctx, **kwargs)
        for identifier, value in zip(identifiers, values):
            kwargs["variable_table"].set_variable(identifier, value)

    def visitExpression(self, ctx: YulParser.ExpressionContext, **kwargs) -> List[Value]:
        assert len(ctx.children) == 1  # pyright: ignore
        child = ctx.children[0]  # pyright: ignore
        ret = self.visit(child, **kwargs)
        return self._extract_values(ret, kwargs["curr_bb"])

    def visitIf(self, ctx: YulParser.IfContext, **kwargs):
        entry_point = BasicBlock(function=kwargs["curr_func"], last_loop_entry=kwargs["last_loop_entry"])
        exp_ctx = ctx.children[1]  # pyright: ignore
        assert isinstance(exp_ctx, YulParser.ExpressionContext)
        kwargs["curr_bb"] = entry_point
        exp = self.visit(exp_ctx, **kwargs)
        assert isinstance(exp, list) and len(exp) == 1
        condition = exp[0]

        vt_origin = kwargs["variable_table"]
        vt_false = vt_origin.copy()
        vt_true = vt_origin.copy()

        kwargs["variable_table"] = vt_true
        block_ctx = ctx.children[2]  # pyright: ignore
        assert isinstance(block_ctx, YulParser.BlockContext)
        true_block_data = self.visit(block_ctx, **kwargs)

        exit_point = BasicBlock(function=kwargs["curr_func"], last_loop_entry=kwargs["last_loop_entry"])
        BranchInst(condition, [true_block_data.entry_point, exit_point], entry_point)

        if true_block_data.exit_point is not None:
            BranchInst(None, [exit_point], true_block_data.exit_point)
            self._generate_phi(
                [entry_point, true_block_data.exit_point],
                [vt_false, vt_true],
                vt_origin,
                exit_point,
            )

        if (
            true_block_data.exit_point is None
            and entry_point.current_loop_entry is not None
            and entry_point.current_loop_entry.loop_compare is None
            and len(true_block_data.entry_point.instructions) == 0
            and len(true_block_data.break_bbs) == 1
            and true_block_data.break_bbs[0][0] == true_block_data.entry_point
        ):
            entry_point.current_loop_entry.loop_compare = entry_point

        if (
            isinstance(ctx.parentCtx.parentCtx.parentCtx, YulParser.ForLoopContext)  # for loop
            and ctx.parentCtx.parentCtx.children[1] is ctx.parentCtx
            and entry_point.current_loop_entry.loop_compare is not None  # loop_compare
            and entry_point.current_loop_entry.loop_compare != entry_point  # entry_point is not loop_compare
        ):
            assert entry_point.current_loop_entry.do_while_compare is None
            entry_point.current_loop_entry.do_while_compare = entry_point

        return BlockReturnData(
            entry_point=entry_point,
            exit_point=exit_point,
            continue_bbs=true_block_data.continue_bbs,
            break_bbs=true_block_data.break_bbs,
            leave_bbs=true_block_data.leave_bbs,
        )

    def visitSwitch(self, ctx: YulParser.SwitchContext, **kwargs):
        # switchInst, entry->cases, cases->exit, phi
        @dataclass
        class SwitchCase:
            case_value: Optional[Constant]
            entry_point: Optional[BasicBlock]
            exit_point: Optional[BasicBlock]
            variable_table: VariableTable

        cases: List[SwitchCase] = []
        block_data = BlockReturnData(
            entry_point=BasicBlock(function=kwargs["curr_func"], last_loop_entry=kwargs["last_loop_entry"]),
            exit_point=BasicBlock(kwargs["curr_func"], last_loop_entry=kwargs["last_loop_entry"]),
            continue_bbs=[],
            break_bbs=[],
            leave_bbs=[],
        )

        kwargs["curr_bb"] = block_data.entry_point
        condition_ctx = ctx.children[1]  # pyright: ignore
        assert isinstance(condition_ctx, YulParser.ExpressionContext)
        exp = self.visit(condition_ctx, **kwargs)
        assert isinstance(exp, list) and len(exp) == 1
        condition = exp[0]

        vt_origin = kwargs["variable_table"]
        del kwargs["variable_table"]

        for child in ctx.children[2:]:  # pyright: ignore
            if isinstance(child, YulParser.CaseContext):
                _, case_ctx, block_ctx = child.children  # pyright: ignore
                assert isinstance(case_ctx, YulParser.LiteralContext)
                assert isinstance(block_ctx, YulParser.BlockContext)
                case_value = self.visit(case_ctx, **kwargs)
                assert case_value is not None
            else:
                assert isinstance(child, YulParser.DefaultContext)
                case_value = None
                _, block_ctx = child.children  # pyright: ignore

            vt_case = vt_origin.copy()
            assert isinstance(block_ctx, YulParser.BlockContext)
            case_data: BlockReturnData = self.visit(block_ctx, variable_table=vt_case, **kwargs)
            block_data.continue_bbs.extend(case_data.continue_bbs)
            block_data.break_bbs.extend(case_data.break_bbs)
            block_data.leave_bbs.extend(case_data.leave_bbs)

            cases.append(
                SwitchCase(
                    case_value=case_value,
                    entry_point=case_data.entry_point,
                    exit_point=case_data.exit_point,
                    variable_table=vt_case,
                )
            )

        if cases[-1].case_value is None:
            default_bb = cases[-1].entry_point
        else:
            default_bb = BasicBlock(function=kwargs["curr_func"], last_loop_entry=kwargs["last_loop_entry"])
            if self._is_bool(condition) and len(cases) == 2:
                UnreachableInst(basic_block=default_bb)
                exit_point = None
            else:
                exit_point = default_bb

            cases.append(
                SwitchCase(
                    case_value=None,
                    entry_point=default_bb,
                    exit_point=exit_point,
                    variable_table=vt_origin.copy(),
                )
            )

        case_succs = []
        for case in cases:
            if case.case_value is not None:
                case_succs.append(case.case_value)
                case_succs.append(case.entry_point)
        switch_inst = SwitchInst(
            condition,
            default_bb,
            case_succs,
            block_data.entry_point,  # pyright: ignore
            yul_source_map=self._get_source_map(ctx),
        )

        predecessors = []
        variable_tables = []
        for case in cases:
            if case.exit_point is not None:
                BranchInst(None, [block_data.exit_point], case.exit_point)  # pyright: ignore
                predecessors.append(case.exit_point)
                variable_tables.append(case.variable_table)

        if len(predecessors) != 0:
            self._generate_phi(predecessors, variable_tables, vt_origin, block_data.exit_point)
        else:
            block_data.exit_point = None

        # NOTE dispatcher
        if kwargs["curr_func"].name == "__runtime":
            self.contract.dispatcher = {}
            for _case, _succ in switch_inst.case_to_successor.items():
                _selector = _case.value
                assert isinstance(_selector, int)
                _func = self._get_external_func_from_dispatcher(_succ)
                self.contract.dispatcher[_selector] = _func
                _func.selector = _selector

        return block_data

    def visitCase(self, ctx: YulParser.CaseContext, **kwargs):
        raise NotImplementedError

    def visitDefault(self, ctx: YulParser.DefaultContext, **kwargs):
        raise NotImplementedError

    def visitForLoop(self, ctx: YulParser.ForLoopContext, **kwargs):
        for_data = BlockReturnData()
        for_data.exit_point = BasicBlock(function=kwargs["curr_func"], last_loop_entry=kwargs["last_loop_entry"])
        kwargs["variable_table"].append_scope()
        _, init_ctx, cmp_ctx, tail_ctx, body_ctx = ctx.children  # pyright: ignore
        self.for_init_blocks.add(init_ctx)

        init_data: BlockReturnData = self.visit(init_ctx, **kwargs)
        assert init_data.exit_point is not None
        for_data.continue_bbs.extend(init_data.continue_bbs)
        for_data.break_bbs.extend(init_data.break_bbs)
        for_data.leave_bbs.extend(init_data.leave_bbs)
        for_data.entry_point = init_data.entry_point

        # NOTE cmp_bb is loop_entry
        cmp_bb = BasicBlock(
            function=kwargs["curr_func"],
            last_loop_entry=kwargs["last_loop_entry"],
            is_loop_entry=True,
        )
        kwargs["last_loop_entry"] = cmp_bb
        BranchInst(None, [cmp_bb], init_data.exit_point)
        kwargs["curr_bb"] = cmp_bb

        # add phi
        name2phi = {}
        for name in self.for2assignment_name[ctx]:
            try:
                old_value = kwargs["variable_table"].get_variable_value(name)
            except KeyError:
                pass
            else:
                phi = PHINode([init_data.entry_point], [old_value], cmp_bb)  # pyright: ignore
                name2phi[name] = phi
                kwargs["variable_table"].set_variable(name, phi)

        exp = self.visit(cmp_ctx, **kwargs)
        assert isinstance(exp, list) and len(exp) == 1
        cmp_value = exp[0]

        if isinstance(cmp_value, ConstantInt):
            assert cmp_value.value == 1, f"unsupported for loop condition {cmp_value.value}"
        else:
            cmp_bb.loop_compare = cmp_bb

        vt_origin = kwargs["variable_table"]
        del kwargs["variable_table"]

        vt_body = vt_origin.copy()
        body_data: BlockReturnData = self.visit(body_ctx, variable_table=vt_body, **kwargs)
        for_data.leave_bbs.extend(body_data.leave_bbs)
        BranchInst(cmp_value, [body_data.entry_point, for_data.exit_point], cmp_bb)  # pyright: ignore

        for predecessor, _ in body_data.break_bbs:
            BranchInst(None, [for_data.exit_point], predecessor)
        to_out_bbs = body_data.break_bbs + [(cmp_bb, vt_origin.copy())]
        self._generate_phi(*zip(*to_out_bbs), vt_origin, for_data.exit_point)  # pyright: ignore

        body_tail_bb = BasicBlock(function=kwargs["curr_func"], last_loop_entry=cmp_bb)
        if body_data.exit_point is None:
            to_body_tail_bbs = body_data.continue_bbs
        else:
            to_body_tail_bbs = body_data.continue_bbs + [(body_data.exit_point, vt_body.copy())]

        if len(to_body_tail_bbs) != 0:
            self._generate_phi(*zip(*to_body_tail_bbs), vt_body, body_tail_bb)  # pyright: ignore
            for predecessor, _ in to_body_tail_bbs:
                BranchInst(None, [body_tail_bb], predecessor)

            tail_data: BlockReturnData = self.visit(tail_ctx, variable_table=vt_body, **kwargs)
            assert tail_data.entry_point and tail_data.exit_point
            assert not tail_data.continue_bbs
            assert not tail_data.break_bbs
            assert not tail_data.leave_bbs
            BranchInst(None, [tail_data.entry_point], body_tail_bb)
            BranchInst(None, [cmp_bb], tail_data.exit_point)

            # update phi
            for name in self.for2assignment_name[ctx]:
                try:
                    new_value = vt_body.get_variable_value(name)
                except KeyError:
                    pass
                else:
                    phi = name2phi[name]
                    assert len(phi.values) == 1
                    if new_value.id == phi.id or new_value.id == phi.values[0].id:
                        phi.add_predecessor(tail_data.exit_point, phi.values[0])
                    else:
                        phi.add_predecessor(tail_data.exit_point, new_value)

        vt_origin.pop_scope()
        return for_data

    def visitBreakContinue(self, ctx: YulParser.BreakContinueContext, **kwargs):
        raise NotImplementedError

    def visitLeave(self, ctx: YulParser.LeaveContext, **kwargs):
        raise NotImplementedError

    def visitFunctionCall(self, ctx: YulParser.FunctionCallContext, **kwargs) -> Instruction:
        identifier_ctx = ctx.children[0]  # pyright: ignore
        assert isinstance(identifier_ctx, YulParser.IdentifierContext)
        func_name = self.visit(identifier_ctx, only_name=True, **kwargs)

        reversed_args = []
        n = len(ctx.children)  # pyright: ignore
        if n > 3:
            assert n % 2 == 0
            for i in range(n - 2, 1, -2):
                expression_ctx = ctx.children[i]  # pyright: ignore
                assert isinstance(expression_ctx, YulParser.ExpressionContext)
                exp = self.visit(expression_ctx, **kwargs)
                assert isinstance(exp, list) and len(exp) == 1
                reversed_args.append(exp[0])
            assert len(reversed_args) == (n - 3 + 1) // 2
        args = list(reversed(reversed_args))
        bb = kwargs["curr_bb"]

        yul_source_map = self._get_source_map(ctx)
        if func_name in all_yul_instructions_dict:
            inst = all_yul_instructions_dict[func_name](args=args, basic_block=bb, yul_source_map=yul_source_map)
        elif func_name in all_evm_instructions_dict:
            inst = all_evm_instructions_dict[func_name](args=args, basic_block=bb, yul_source_map=yul_source_map)
            assert len(args) == inst.n_args
            if inst.is_halt_inst:
                UnreachableInst(basic_block=bb, yul_source_map=yul_source_map)
                stmt = ctx.parentCtx.parentCtx
                assert isinstance(stmt, YulParser.StatementContext)
        else:
            func = self._get_func(func_name, kwargs["is_runtime"])
            inst = CallInst(function=func, args=args, basic_block=bb, yul_source_map=yul_source_map)
            assert len(args) == len(func.arguments)

            if func.id not in self.start_func_id:
                self.visit(self.func_id2ctx[func.id], **kwargs)

        return inst

    def visitIdentifier(self, ctx: YulParser.IdentifierContext, only_name=False, **kwargs):
        name = ctx.getText()
        if only_name:
            return name
        else:
            value = kwargs["variable_table"].get_variable_value(name)
            return value

    def visitIdentifierList(self, ctx: YulParser.IdentifierListContext, **kwargs) -> List[str]:
        return [
            self.visit(ctx.children[i], only_name=True, **kwargs) for i in range(0, len(ctx.children), 2)
        ]  # pyright: ignore

    def visitTypeName(self, ctx: YulParser.TypeNameContext, **kwargs) -> str:
        return self.visit(ctx.children[0])  # pyright: ignore

    def visitTypedIdentifierList(self, ctx: YulParser.TypedIdentifierListContext, **kwargs) -> List[str]:
        identifiers = []
        for child in ctx.children:  # pyright: ignore
            if isinstance(child, YulParser.TypeNameContext):
                raise NotImplementedError
            if isinstance(child, YulParser.IdentifierContext):
                identifiers.append(self.visit(child, only_name=True, **kwargs))
        return identifiers

    def visitLiteral(self, ctx: YulParser.LiteralContext, **kwargs) -> Constant:
        value = self.visit(ctx.children[0])  # pyright: ignore
        if len(ctx.children) == 3:  # pyright: ignore
            identifier_ctx = ctx.children[2]  # pyright: ignore
            assert isinstance(identifier_ctx, YulParser.IdentifierContext)
            type_name = self.visit(identifier_ctx, only_name=True, **kwargs)
            value.type_name = type_name
        return value

    def visitNumberLiteral(self, ctx: YulParser.NumberLiteralContext, **kwargs) -> ConstantInt:
        return self.visit(ctx.children[0])  # pyright: ignore

    def visitStringLiteral(self, ctx: YulParser.StringLiteralContext, **kwargs):
        return ConstantStr(self.contract.id_group, value=ast.literal_eval(ctx.getText()))

    def visitHexStringLiteral(self, ctx: YulParser.HexStringLiteralContext, **kwargs):
        text = ctx.getText()
        assert len(text) >= 5
        assert text.startswith('hex"')
        assert text.endswith('"')
        return ConstantHexStr(self.contract.id_group, value=text[4:-1])

    def visitTrueLiteral(self, ctx: YulParser.TrueLiteralContext, **kwargs):
        return ConstantBool(self.contract.id_group, value=True)

    def visitFalseLiteral(self, ctx: YulParser.FalseLiteralContext, **kwargs):
        return ConstantBool(self.contract.id_group, value=False)

    def visitHexNumber(self, ctx: YulParser.HexNumberContext, **kwargs):
        return ConstantInt(self.contract.id_group, value=int(ctx.getText(), 16))

    def visitDecimalNumber(self, ctx: YulParser.DecimalNumberContext, **kwargs):
        return ConstantInt(self.contract.id_group, value=int(ctx.getText(), 10))
