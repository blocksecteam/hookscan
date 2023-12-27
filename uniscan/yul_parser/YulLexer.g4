lexer grammar YulLexer;
channels {
	MULTI_LINE_COMMENT_CHANNEL,
	SINGLE_LINE_COMMENT,
	WHITE_SPACE
}
OBJECT: 'object';
CODE: 'code';
DATA: 'data';
HEX: 'hex';
FUNCTION: 'function';
LET: 'let';
IF: 'if';
SWITCH: 'switch';
CASE: 'case';
DEFAULT: 'default';
FOR: 'for';
BREAK: 'break';
CONTINUE: 'continue';
LEAVE: 'leave';

LPAREN: '(';
RPAREN: ')';
LBRACE: '{';
RBRACE: '}';

ASSIGN: ':=';

SEMI: ';';
COMMA: ',';
COLON: ':';
ARROW: '->';

IDENTIFIER: [a-zA-Z_$] [a-zA-Z_$0-9.]*;
STRINGLITERAL: '"' (~["\r\n\\] | '\\' .)* '"';
HEXSTRINGLITERAL: HEX '"' ([0-9a-fA-F] [0-9a-fA-F])* '"';
TRUELITERAL: 'true';
FALSELITERAL: 'false';
HEXNUMBER: '0x' [0-9a-fA-F]+;
DECIMALNUMBER: [0-9] | ([1-9] [0-9]+);

COMMENT: '/*' .*? '*/' -> channel(MULTI_LINE_COMMENT_CHANNEL);
LINECOMMENT: '//' ~[\r\n]* -> channel(SINGLE_LINE_COMMENT);
WS: [ \t\r\n]+ -> channel(WHITE_SPACE);
