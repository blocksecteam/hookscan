from antlr4 import CommonTokenStream, InputStream
from antlr4.error.ErrorListener import ErrorListener

from uniscan.components.contract import Contract
from uniscan.yul_parser.antlr.YulLexer import YulLexer
from uniscan.yul_parser.antlr.YulParser import YulParser
from uniscan.yul_parser.visitor import Visitor


class MyErrorListener(ErrorListener):
    def syntaxError(self, recognizer, offendingSymbol, line, column, msg, e):
        raise ValueError("line " + str(line) + ":" + str(column) + " " + msg)

    def reportAmbiguity(self, *args, **kwargs):
        raise ValueError(*args, **kwargs)

    def reportAttemptingFullContext(self, *args, **kwargs):
        raise ValueError(*args, **kwargs)

    def reportContextSensitivity(self, *args, **kwargs):
        raise ValueError(*args, **kwargs)


def _get_tree(yul_content):
    input_stream = InputStream(yul_content)
    lexer = YulLexer(input_stream)
    lexer.removeErrorListeners()
    lexer.addErrorListener(MyErrorListener())
    stream = CommonTokenStream(lexer)
    parser = YulParser(stream)
    parser.removeErrorListeners()
    parser.addErrorListener(MyErrorListener())
    tree = parser.prog()
    return tree


def parse_yul(yul_content) -> Contract:
    tree = _get_tree(yul_content)
    visitor = Visitor()
    contract: Contract = visitor.visit(tree)
    contract.yul_list_by_line = yul_content.split("\n")
    return contract
