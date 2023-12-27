# Generated from uniscan/yul_parser/YulParser.g4 by ANTLR 4.10.1
from antlr4 import *

if __name__ is not None and "." in __name__:
    from .YulParser import YulParser
else:
    from YulParser import YulParser

# This class defines a complete generic visitor for a parse tree produced by YulParser.


class YulParserVisitor(ParseTreeVisitor):

    # Visit a parse tree produced by YulParser#prog.
    def visitProg(self, ctx: YulParser.ProgContext):
        return self.visitChildren(ctx)

    # Visit a parse tree produced by YulParser#object.
    def visitObject(self, ctx: YulParser.ObjectContext):
        return self.visitChildren(ctx)

    # Visit a parse tree produced by YulParser#code.
    def visitCode(self, ctx: YulParser.CodeContext):
        return self.visitChildren(ctx)

    # Visit a parse tree produced by YulParser#data.
    def visitData(self, ctx: YulParser.DataContext):
        return self.visitChildren(ctx)

    # Visit a parse tree produced by YulParser#block.
    def visitBlock(self, ctx: YulParser.BlockContext):
        return self.visitChildren(ctx)

    # Visit a parse tree produced by YulParser#statement.
    def visitStatement(self, ctx: YulParser.StatementContext):
        return self.visitChildren(ctx)

    # Visit a parse tree produced by YulParser#functionDefinition.
    def visitFunctionDefinition(self, ctx: YulParser.FunctionDefinitionContext):
        return self.visitChildren(ctx)

    # Visit a parse tree produced by YulParser#variableDeclaration.
    def visitVariableDeclaration(self, ctx: YulParser.VariableDeclarationContext):
        return self.visitChildren(ctx)

    # Visit a parse tree produced by YulParser#assignment.
    def visitAssignment(self, ctx: YulParser.AssignmentContext):
        return self.visitChildren(ctx)

    # Visit a parse tree produced by YulParser#expression.
    def visitExpression(self, ctx: YulParser.ExpressionContext):
        return self.visitChildren(ctx)

    # Visit a parse tree produced by YulParser#if.
    def visitIf(self, ctx: YulParser.IfContext):
        return self.visitChildren(ctx)

    # Visit a parse tree produced by YulParser#switch.
    def visitSwitch(self, ctx: YulParser.SwitchContext):
        return self.visitChildren(ctx)

    # Visit a parse tree produced by YulParser#case.
    def visitCase(self, ctx: YulParser.CaseContext):
        return self.visitChildren(ctx)

    # Visit a parse tree produced by YulParser#default.
    def visitDefault(self, ctx: YulParser.DefaultContext):
        return self.visitChildren(ctx)

    # Visit a parse tree produced by YulParser#forLoop.
    def visitForLoop(self, ctx: YulParser.ForLoopContext):
        return self.visitChildren(ctx)

    # Visit a parse tree produced by YulParser#breakContinue.
    def visitBreakContinue(self, ctx: YulParser.BreakContinueContext):
        return self.visitChildren(ctx)

    # Visit a parse tree produced by YulParser#leave.
    def visitLeave(self, ctx: YulParser.LeaveContext):
        return self.visitChildren(ctx)

    # Visit a parse tree produced by YulParser#functionCall.
    def visitFunctionCall(self, ctx: YulParser.FunctionCallContext):
        return self.visitChildren(ctx)

    # Visit a parse tree produced by YulParser#identifier.
    def visitIdentifier(self, ctx: YulParser.IdentifierContext):
        return self.visitChildren(ctx)

    # Visit a parse tree produced by YulParser#identifierList.
    def visitIdentifierList(self, ctx: YulParser.IdentifierListContext):
        return self.visitChildren(ctx)

    # Visit a parse tree produced by YulParser#typeName.
    def visitTypeName(self, ctx: YulParser.TypeNameContext):
        return self.visitChildren(ctx)

    # Visit a parse tree produced by YulParser#typedIdentifierList.
    def visitTypedIdentifierList(self, ctx: YulParser.TypedIdentifierListContext):
        return self.visitChildren(ctx)

    # Visit a parse tree produced by YulParser#literal.
    def visitLiteral(self, ctx: YulParser.LiteralContext):
        return self.visitChildren(ctx)

    # Visit a parse tree produced by YulParser#numberLiteral.
    def visitNumberLiteral(self, ctx: YulParser.NumberLiteralContext):
        return self.visitChildren(ctx)

    # Visit a parse tree produced by YulParser#stringLiteral.
    def visitStringLiteral(self, ctx: YulParser.StringLiteralContext):
        return self.visitChildren(ctx)

    # Visit a parse tree produced by YulParser#hexStringLiteral.
    def visitHexStringLiteral(self, ctx: YulParser.HexStringLiteralContext):
        return self.visitChildren(ctx)

    # Visit a parse tree produced by YulParser#trueLiteral.
    def visitTrueLiteral(self, ctx: YulParser.TrueLiteralContext):
        return self.visitChildren(ctx)

    # Visit a parse tree produced by YulParser#falseLiteral.
    def visitFalseLiteral(self, ctx: YulParser.FalseLiteralContext):
        return self.visitChildren(ctx)

    # Visit a parse tree produced by YulParser#hexNumber.
    def visitHexNumber(self, ctx: YulParser.HexNumberContext):
        return self.visitChildren(ctx)

    # Visit a parse tree produced by YulParser#decimalNumber.
    def visitDecimalNumber(self, ctx: YulParser.DecimalNumberContext):
        return self.visitChildren(ctx)


del YulParser
