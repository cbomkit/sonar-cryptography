/*
 * Simplified C# Lexer Grammar for Crypto Detection
 *
 * Handles lexical analysis of C# source code sufficient for detecting
 * cryptographic API usage patterns in System.Security.Cryptography and
 * BouncyCastle.NetCore.
 *
 * Based on patterns from the ANTLR4 grammars-v4 C# grammar:
 * https://github.com/antlr/grammars-v4/tree/master/csharp
 */
lexer grammar CSharpLexer;

// -----------------------------------------------
// Keywords
// -----------------------------------------------
ABSTRACT:       'abstract';
AS:             'as';
BASE:           'base';
BOOL:           'bool';
BREAK:          'break';
BYTE:           'byte';
CASE:           'case';
CATCH:          'catch';
CHAR:           'char';
CLASS:          'class';
CONST:          'const';
CONTINUE:       'continue';
DECIMAL_KW:     'decimal';
DEFAULT:        'default';
DELEGATE:       'delegate';
DO:             'do';
DOUBLE_KW:      'double';
ELSE:           'else';
ENUM:           'enum';
EVENT:          'event';
EXPLICIT:       'explicit';
EXTERN:         'extern';
FALSE:          'false';
FINALLY:        'finally';
FIXED:          'fixed';
FLOAT_KW:       'float';
FOR:            'for';
FOREACH:        'foreach';
GOTO:           'goto';
IF:             'if';
IMPLICIT:       'implicit';
IN:             'in';
INT_KW:         'int';
INTERFACE:      'interface';
INTERNAL:       'internal';
IS:             'is';
LOCK:           'lock';
LONG_KW:        'long';
NAMESPACE:      'namespace';
NEW:            'new';
NULL:           'null';
OBJECT_KW:      'object';
OPERATOR:       'operator';
OUT:            'out';
OVERRIDE:       'override';
PARAMS:         'params';
PARTIAL:        'partial';
PRIVATE:        'private';
PROTECTED:      'protected';
PUBLIC:         'public';
READONLY:       'readonly';
REF:            'ref';
RETURN:         'return';
SBYTE:          'sbyte';
SEALED:         'sealed';
SHORT_KW:       'short';
SIZEOF:         'sizeof';
STACKALLOC:     'stackalloc';
STATIC:         'static';
STRING_KW:      'string';
STRUCT:         'struct';
SWITCH:         'switch';
THIS:           'this';
THROW:          'throw';
TRUE:           'true';
TRY:            'try';
TYPEOF:         'typeof';
UINT:           'uint';
ULONG:          'ulong';
UNCHECKED:      'unchecked';
UNSAFE:         'unsafe';
USHORT:         'ushort';
USING:          'using';
VIRTUAL:        'virtual';
VOID:           'void';
VOLATILE:       'volatile';
WHILE:          'while';
ASYNC:          'async';
AWAIT:          'await';
VAR:            'var';
DYNAMIC:        'dynamic';
GET:            'get';
SET:            'set';
INIT:           'init';
NAMEOF:         'nameof';
WHEN:           'when';
YIELD:          'yield';
ADD:            'add';
REMOVE:         'remove';
FROM:           'from';
WHERE:          'where';
SELECT:         'select';
LET:            'let';
ORDERBY:        'orderby';
ASCENDING:      'ascending';
DESCENDING:     'descending';
JOIN:           'join';
ON:             'on';
EQUALS:         'equals';
INTO:           'into';
GROUP:          'group';
BY:             'by';
RECORD:         'record';
REQUIRED:       'required';
FILE:           'file';
UNMANAGED:      'unmanaged';
NOT:            'not';
OR:             'or';
AND:            'and';
WITH:           'with';
GLOBAL:         'global';
ALIAS:          'alias';
ASSEMBLY:       'assembly';
MODULE:         'module';
NOTNULL:        'notnull';

// -----------------------------------------------
// Literals
// -----------------------------------------------
INTEGER_LITERAL
    : DECIMAL_DIGITS INTEGER_TYPE_SUFFIX?
    | HEX_DIGITS INTEGER_TYPE_SUFFIX?
    | BINARY_DIGITS INTEGER_TYPE_SUFFIX?
    ;

REAL_LITERAL
    : DECIMAL_DIGITS '.' DECIMAL_DIGITS EXPONENT_PART? REAL_TYPE_SUFFIX?
    | '.' DECIMAL_DIGITS EXPONENT_PART? REAL_TYPE_SUFFIX?
    | DECIMAL_DIGITS EXPONENT_PART REAL_TYPE_SUFFIX?
    | DECIMAL_DIGITS REAL_TYPE_SUFFIX
    ;

CHARACTER_LITERAL
    : '\'' CHARACTER '\''
    ;

REGULAR_STRING
    : '"' REGULAR_STRING_CHARACTER* '"'
    ;

VERBATIM_STRING
    : '@"' VERBATIM_STRING_CHARACTER* '"'
    ;

// Interpolated strings (simplified - just consume them)
INTERPOLATED_REGULAR_STRING
    : '$"' INTERPOLATED_CHAR* '"'
    ;

INTERPOLATED_VERBATIM_STRING
    : '$@"' (~'"' | '""')* '"'
    | '@$"' (~'"' | '""')* '"'
    ;

// -----------------------------------------------
// Separators and operators
// -----------------------------------------------
OPEN_BRACE:             '{';
CLOSE_BRACE:            '}';
OPEN_BRACKET:           '[';
CLOSE_BRACKET:          ']';
OPEN_PARENS:            '(';
CLOSE_PARENS:           ')';
DOT:                    '.';
COMMA:                  ',';
COLON:                  ':';
SEMICOLON:              ';';
PLUS:                   '+';
MINUS:                  '-';
STAR:                   '*';
DIV:                    '/';
PERCENT:                '%';
AMP:                    '&';
BITWISE_OR:             '|';
CARET:                  '^';
BANG:                   '!';
TILDE:                  '~';
ASSIGNMENT:             '=';
LT:                     '<';
GT:                     '>';
INTERR:                 '?';
DOUBLE_COLON:           '::';
OP_COALESCING:          '??';
OP_INC:                 '++';
OP_DEC:                 '--';
OP_AND:                 '&&';
OP_OR:                  '||';
OP_PTR:                 '->';
OP_EQ:                  '==';
OP_NE:                  '!=';
OP_LE:                  '<=';
OP_GE:                  '>=';
OP_ADD_ASSIGNMENT:      '+=';
OP_SUB_ASSIGNMENT:      '-=';
OP_MULT_ASSIGNMENT:     '*=';
OP_DIV_ASSIGNMENT:      '/=';
OP_MOD_ASSIGNMENT:      '%=';
OP_AND_ASSIGNMENT:      '&=';
OP_OR_ASSIGNMENT:       '|=';
OP_XOR_ASSIGNMENT:      '^=';
OP_LEFT_SHIFT:          '<<';
OP_RIGHT_SHIFT:         '>>';
OP_LEFT_SHIFT_ASSIGNMENT:   '<<=';
OP_RIGHT_SHIFT_ASSIGNMENT:  '>>=';
OP_UNSIGNED_RIGHT_SHIFT:    '>>>';
OP_UNSIGNED_RIGHT_SHIFT_ASSIGNMENT: '>>>=';
OP_RANGE:               '..';
OP_LAMBDA:              '=>';
DOUBLE_QUESTION_MARK_ASSIGNMENT: '??=';
// Null conditional
OP_NULL_DOT:            '?.';
OP_NULL_BRACKET:        '?[';

// -----------------------------------------------
// Identifiers
// -----------------------------------------------
IDENTIFIER
    : ('@' | LETTER_OR_UNDERSCORE) LETTER_OR_DIGIT*
    ;

// -----------------------------------------------
// Whitespace and comments (skipped)
// -----------------------------------------------
WS
    : [ \t\r\n\u000C\u000B]+ -> channel(HIDDEN)
    ;

SINGLE_LINE_COMMENT
    : '//' ~[\r\n]* -> channel(HIDDEN)
    ;

DELIMITED_COMMENT
    : '/*' .*? '*/' -> channel(HIDDEN)
    ;

// Preprocessor directives (simplified - skip entire line)
PREPROCESSOR_DIRECTIVE
    : '#' ~[\r\n]* -> channel(HIDDEN)
    ;

// -----------------------------------------------
// Fragments
// -----------------------------------------------
fragment DECIMAL_DIGITS:    DECIMAL_DIGIT ('_'? DECIMAL_DIGIT)*;
fragment DECIMAL_DIGIT:     [0-9];
fragment HEX_DIGITS:        '0' [xX] HEX_DIGIT ('_'? HEX_DIGIT)*;
fragment HEX_DIGIT:         [0-9a-fA-F];
fragment BINARY_DIGITS:     '0' [bB] BINARY_DIGIT ('_'? BINARY_DIGIT)*;
fragment BINARY_DIGIT:      [01];
fragment INTEGER_TYPE_SUFFIX
    : 'U' | 'u' | 'L' | 'l' | 'UL' | 'Ul' | 'uL' | 'ul' | 'LU' | 'Lu' | 'lU' | 'lu'
    ;
fragment EXPONENT_PART:     [eE] [+-]? DECIMAL_DIGITS;
fragment REAL_TYPE_SUFFIX:  [fFdDmM];

fragment CHARACTER
    : ~['\\\r\n\u0085\u2028\u2029]
    | SIMPLE_ESCAPE_SEQUENCE
    | HEX_ESCAPE_SEQUENCE
    | UNICODE_ESCAPE_SEQUENCE
    ;

fragment REGULAR_STRING_CHARACTER
    : ~["\\\r\n\u0085\u2028\u2029]
    | SIMPLE_ESCAPE_SEQUENCE
    | HEX_ESCAPE_SEQUENCE
    | UNICODE_ESCAPE_SEQUENCE
    ;

fragment VERBATIM_STRING_CHARACTER
    : ~'"'
    | '""'
    ;

fragment INTERPOLATED_CHAR
    : ~["{\\]
    | '\\' .
    | '{' ~[{] // simplified interpolated expression
    ;

fragment SIMPLE_ESCAPE_SEQUENCE
    : '\\' [\\'0abfnrtuUvx]
    ;

fragment HEX_ESCAPE_SEQUENCE
    : '\\x' HEX_DIGIT HEX_DIGIT? HEX_DIGIT? HEX_DIGIT?
    ;

fragment UNICODE_ESCAPE_SEQUENCE
    : '\\u' HEX_DIGIT HEX_DIGIT HEX_DIGIT HEX_DIGIT
    | '\\U' HEX_DIGIT HEX_DIGIT HEX_DIGIT HEX_DIGIT HEX_DIGIT HEX_DIGIT HEX_DIGIT HEX_DIGIT
    ;

fragment LETTER_OR_UNDERSCORE: [a-zA-Z_\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD];
fragment LETTER_OR_DIGIT: [a-zA-Z_0-9\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD];
