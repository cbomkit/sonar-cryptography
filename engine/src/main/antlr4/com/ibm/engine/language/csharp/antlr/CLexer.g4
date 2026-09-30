/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * C Lexer Grammar for CBOMkit sonar-cryptography plugin.
 * Adapted from the ANTLR4 grammars-v4 C grammar:
 * https://github.com/antlr/grammars-v4/tree/master/c
 *
 * Supports C89, C99, C11 constructs sufficient for detecting
 * OpenSSL and other cryptographic library API calls.
 */
lexer grammar CLexer;

// ---------------------------------------------------------------------------
// Keywords
// ---------------------------------------------------------------------------

Auto        : 'auto';
Break       : 'break';
Case        : 'case';
Char        : 'char';
Const       : 'const';
Continue    : 'continue';
Default     : 'default';
Do          : 'do';
Double      : 'double';
Else        : 'else';
Enum        : 'enum';
Extern      : 'extern';
Float       : 'float';
For         : 'for';
Goto        : 'goto';
If          : 'if';
Inline      : 'inline';
Int         : 'int';
Long        : 'long';
Register    : 'register';
Restrict    : 'restrict';
Return      : 'return';
Short       : 'short';
Signed      : 'signed';
Sizeof      : 'sizeof';
Static      : 'static';
Struct      : 'struct';
Switch      : 'switch';
Typedef     : 'typedef';
Union       : 'union';
Unsigned    : 'unsigned';
Void        : 'void';
Volatile    : 'volatile';
While       : 'while';

// C11 keywords
Alignas         : '_Alignas';
Alignof         : '_Alignof';
Atomic          : '_Atomic';
Bool            : '_Bool';
Complex         : '_Complex';
Generic         : '_Generic';
Imaginary       : '_Imaginary';
Noreturn        : '_Noreturn';
StaticAssert    : '_Static_assert';
ThreadLocal     : '_Thread_local';

// GCC extensions (common in OpenSSL code)
BuiltinVaArg    : '__builtin_va_arg';
BuiltinOffsetof : '__builtin_offsetof';

// ---------------------------------------------------------------------------
// Punctuators and operators
// ---------------------------------------------------------------------------

LeftParen       : '(';
RightParen      : ')';
LeftBracket     : '[';
RightBracket    : ']';
LeftBrace       : '{';
RightBrace      : '}';

Less            : '<';
LessEqual       : '<=';
Greater         : '>';
GreaterEqual    : '>=';
LeftShift       : '<<';
RightShift      : '>>';

Plus            : '+';
PlusPlus        : '++';
Minus           : '-';
MinusMinus      : '--';
Star            : '*';
Div             : '/';
Mod             : '%';

And             : '&';
Or              : '|';
AndAnd          : '&&';
OrOr            : '||';
Caret           : '^';
Not             : '!';
Tilde           : '~';

Question        : '?';
Colon           : ':';
Semi            : ';';
Comma           : ',';
Assign          : '=';

// Compound assignment operators
StarAssign      : '*=';
DivAssign       : '/=';
ModAssign       : '%=';
PlusAssign      : '+=';
MinusAssign     : '-=';
LeftShiftAssign : '<<=';
RightShiftAssign: '>>=';
AndAssign       : '&=';
XorAssign       : '^=';
OrAssign        : '|=';

Equal           : '==';
NotEqual        : '!=';

Arrow           : '->';
Dot             : '.';
Ellipsis        : '...';

// ---------------------------------------------------------------------------
// Literals
// ---------------------------------------------------------------------------

IntegerConstant
    : DecimalConstant IntegerSuffix?
    | OctalConstant IntegerSuffix?
    | HexadecimalConstant IntegerSuffix?
    | BinaryConstant
    ;

fragment BinaryConstant
    : '0' [bB] [0-1]+
    ;

fragment DecimalConstant
    : NonzeroDigit Digit*
    ;

fragment OctalConstant
    : '0' OctalDigit*
    ;

fragment HexadecimalConstant
    : HexadecimalPrefix HexadecimalDigit+
    ;

fragment HexadecimalPrefix
    : '0' [xX]
    ;

fragment IntegerSuffix
    : UnsignedSuffix LongSuffix?
    | UnsignedSuffix LongLongSuffix
    | LongSuffix UnsignedSuffix?
    | LongLongSuffix UnsignedSuffix?
    ;

fragment UnsignedSuffix
    : [uU]
    ;

fragment LongSuffix
    : [lL]
    ;

fragment LongLongSuffix
    : 'll' | 'LL'
    ;

FloatingConstant
    : DecimalFloatingConstant
    | HexadecimalFloatingConstant
    ;

fragment DecimalFloatingConstant
    : FractionalConstant ExponentPart? FloatingSuffix?
    | DigitSequence ExponentPart FloatingSuffix?
    ;

fragment HexadecimalFloatingConstant
    : HexadecimalPrefix (HexadecimalFractionalConstant | HexadecimalDigitSequence) BinaryExponentPart FloatingSuffix?
    ;

fragment FractionalConstant
    : DigitSequence? '.' DigitSequence
    | DigitSequence '.'
    ;

fragment ExponentPart
    : [eE] Sign? DigitSequence
    ;

fragment Sign
    : [+-]
    ;

fragment DigitSequence
    : Digit+
    ;

fragment HexadecimalFractionalConstant
    : HexadecimalDigitSequence? '.' HexadecimalDigitSequence
    | HexadecimalDigitSequence '.'
    ;

fragment BinaryExponentPart
    : [pP] Sign? DigitSequence
    ;

fragment HexadecimalDigitSequence
    : HexadecimalDigit+
    ;

fragment FloatingSuffix
    : [flFL]
    ;

CharacterConstant
    : '\'' CCharSequence '\''
    | 'L\'' CCharSequence '\''
    | 'u\'' CCharSequence '\''
    | 'U\'' CCharSequence '\''
    ;

fragment CCharSequence
    : CChar+
    ;

fragment CChar
    : ~['\\\r\n]
    | EscapeSequence
    ;

StringLiteral
    : EncodingPrefix? '"' SCharSequence? '"'
    ;

fragment EncodingPrefix
    : 'u8' | 'u' | 'U' | 'L'
    ;

fragment SCharSequence
    : SChar+
    ;

fragment SChar
    : ~["\\\r\n]
    | EscapeSequence
    | '\\\n'    // Added line
    | '\\\r\n'  // Added line
    ;

fragment EscapeSequence
    : SimpleEscapeSequence
    | OctalEscapeSequence
    | HexadecimalEscapeSequence
    | UniversalCharacterName
    ;

fragment SimpleEscapeSequence
    : '\\' ['"?abfnrtvv\\]
    ;

fragment OctalEscapeSequence
    : '\\' OctalDigit OctalDigit? OctalDigit?
    ;

fragment HexadecimalEscapeSequence
    : '\\x' HexadecimalDigit+
    ;

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

Identifier
    : IdentifierNondigit (IdentifierNondigit | Digit)*
    ;

fragment IdentifierNondigit
    : Nondigit
    | UniversalCharacterName
    ;

fragment Nondigit
    : [a-zA-Z_]
    ;

fragment Digit
    : [0-9]
    ;

fragment NonzeroDigit
    : [1-9]
    ;

fragment OctalDigit
    : [0-7]
    ;

fragment HexadecimalDigit
    : [0-9a-fA-F]
    ;

fragment UniversalCharacterName
    : '\\u' HexadecimalDigit HexadecimalDigit HexadecimalDigit HexadecimalDigit
    | '\\U' HexadecimalDigit HexadecimalDigit HexadecimalDigit HexadecimalDigit
              HexadecimalDigit HexadecimalDigit HexadecimalDigit HexadecimalDigit
    ;

// ---------------------------------------------------------------------------
// Preprocessor directives (skip — we do not expand macros)
// ---------------------------------------------------------------------------

Directive
    : '#' ~[\r\n]* -> skip
    ;

// ---------------------------------------------------------------------------
// Whitespace and comments
// ---------------------------------------------------------------------------

Whitespace
    : [ \t]+ -> skip
    ;

Newline
    : ( '\r' '\n'? | '\n' ) -> skip
    ;

BlockComment
    : '/*' .*? '*/' -> skip
    ;

LineComment
    : '//' ~[\r\n]* -> skip
    ;
