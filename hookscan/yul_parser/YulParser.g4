parser grammar YulParser;
options {
	tokenVocab = YulLexer;
}

prog :  object ;

object : OBJECT stringLiteral '{' ( code | object | data )+ '}' ;
code : CODE block ;
data : DATA stringLiteral hexStringLiteral ;

block : '{' statement* '}' ;
statement :
    block |
    functionDefinition |
    variableDeclaration |
    assignment |
    if |
    expression |
    switch |
    forLoop |
    breakContinue |
    leave ;
functionDefinition :
    FUNCTION identifier '(' typedIdentifierList? ','? ')' ( '->' typedIdentifierList )? block ;
variableDeclaration :
    LET typedIdentifierList ( ':=' expression )? ;
assignment :
    identifierList ':=' expression ;
expression :
    functionCall | identifier | literal ;
if :
    IF expression block ;
switch :
    SWITCH expression ( case+ default? | default ) ;
case :
    CASE literal block ;
default :
    DEFAULT block ;
forLoop :
    FOR block expression block block ;
breakContinue :
    BREAK | CONTINUE ;
leave : LEAVE ;
functionCall :
    identifier '(' ( expression ( ',' expression )* )? ')' ;
identifier : IDENTIFIER | OBJECT | CODE | DATA;
identifierList : identifier ( ',' identifier)* ;
typeName : identifier ;
typedIdentifierList : identifier ( ':' typeName )? ( ',' identifier ( ':' typeName )? )* ;
literal :
    (numberLiteral | stringLiteral | hexStringLiteral | trueLiteral | falseLiteral) ( ':' typeName )? ;
numberLiteral : hexNumber | decimalNumber ;
stringLiteral : STRINGLITERAL ;
hexStringLiteral : HEXSTRINGLITERAL ;
trueLiteral : TRUELITERAL ;
falseLiteral : FALSELITERAL ;
hexNumber : HEXNUMBER ;
decimalNumber : DECIMALNUMBER ;
