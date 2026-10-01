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
 * C Parser Grammar for CBOMkit sonar-cryptography plugin.
 * Adapted from the ANTLR4 grammars-v4 C grammar:
 * https://github.com/antlr/grammars-v4/tree/master/c
 *
 * Supports C89, C99, C11 constructs sufficient for detecting
 * OpenSSL and other cryptographic library API calls.
 *
 * Key design goals:
 * - Detect function calls: EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), ...)
 * - Detect string literals used as algorithm identifiers
 * - Detect integer constants used as key sizes
 * - Handle pointer dereferences and struct member access
 */
parser grammar CParser;

options {
    tokenVocab = CLexer;
}

// ---------------------------------------------------------------------------
// Top-level rule
// ---------------------------------------------------------------------------

compilationUnit
    : translationUnit? EOF
    ;

translationUnit
    : externalDeclaration+
    ;

externalDeclaration
    : functionDefinition
    | declaration
    | Semi  // stray semicolons
    ;

// ---------------------------------------------------------------------------
// Function definitions
// ---------------------------------------------------------------------------

functionDefinition
    : declarationSpecifiers declarator declarationList? compoundStatement
    ;

declarationList
    : declaration+
    ;

// ---------------------------------------------------------------------------
// Declarations
// ---------------------------------------------------------------------------

declaration
    : declarationSpecifiers initDeclaratorList? Semi
    | staticAssertDeclaration
    ;

declarationSpecifiers
    : declarationSpecifier+
    ;

declarationSpecifiers2
    : declarationSpecifier+
    ;

declarationSpecifier
    : storageClassSpecifier
    | typeSpecifier
    | typeQualifier
    | functionSpecifier
    | alignmentSpecifier
    ;

initDeclaratorList
    : initDeclarator ( Comma initDeclarator )*
    ;

initDeclarator
    : declarator ( Assign initializer )?
    ;

storageClassSpecifier
    : Typedef
    | Extern
    | Static
    | ThreadLocal
    | Auto
    | Register
    ;

typeSpecifier
    : Void
    | Char
    | Short
    | Int
    | Long
    | Float
    | Double
    | Signed
    | Unsigned
    | Bool
    | Complex
    | atomicTypeSpecifier
    | structOrUnionSpecifier
    | enumSpecifier
    | typedefName
    | typeofSpecifier
    ;

// typeof() — GCC extension common in OpenSSL
typeofSpecifier
    : '__typeof__' LeftParen (expression | typeName) RightParen
    | '__typeof' LeftParen (expression | typeName) RightParen
    ;

structOrUnionSpecifier
    : structOrUnion Identifier? LeftBrace structDeclarationList RightBrace
    | structOrUnion Identifier
    ;

structOrUnion
    : 'struct'
    | 'union'
    ;

structDeclarationList
    : structDeclaration+
    ;

structDeclaration
    : specifierQualifierList structDeclaratorList? Semi
    | staticAssertDeclaration
    ;

specifierQualifierList
    : (typeSpecifier | typeQualifier | alignmentSpecifier)+
    ;

structDeclaratorList
    : structDeclarator (Comma structDeclarator)*
    ;

structDeclarator
    : declarator
    | declarator? Colon constantExpression
    ;

enumSpecifier
    : 'enum' Identifier? LeftBrace enumeratorList Comma? RightBrace
    | 'enum' Identifier
    ;

enumeratorList
    : enumerator (Comma enumerator)*
    ;

enumerator
    : enumerationConstant (Assign constantExpression)?
    ;

enumerationConstant
    : Identifier
    ;

atomicTypeSpecifier
    : Atomic LeftParen typeName RightParen
    ;

typeQualifier
    : Const
    | Restrict
    | Volatile
    | Atomic
    ;

functionSpecifier
    : Inline
    | Noreturn
    ;

alignmentSpecifier
    : Alignas LeftParen (typeName | constantExpression) RightParen
    ;

declarator
    : pointer? directDeclarator
    ;

directDeclarator
    : Identifier
    | LeftParen declarator RightParen
    | directDeclarator LeftBracket typeQualifierList? assignmentExpression? RightBracket
    | directDeclarator LeftBracket Static typeQualifierList? assignmentExpression RightBracket
    | directDeclarator LeftBracket typeQualifierList Static assignmentExpression RightBracket
    | directDeclarator LeftBracket typeQualifierList? Star RightBracket
    | directDeclarator LeftParen parameterTypeList RightParen
    | directDeclarator LeftParen identifierList? RightParen
    ;

pointer
    : ( Star typeQualifierList? )+
    ;

typeQualifierList
    : typeQualifier+
    ;

parameterTypeList
    : parameterList ( Comma Ellipsis )?
    ;

parameterList
    : parameterDeclaration ( Comma parameterDeclaration )*
    ;

parameterDeclaration
    : declarationSpecifiers declarator
    | declarationSpecifiers2 abstractDeclarator?
    ;

identifierList
    : Identifier ( Comma Identifier )*
    ;

typeName
    : specifierQualifierList abstractDeclarator?
    ;

abstractDeclarator
    : pointer
    | pointer? directAbstractDeclarator
    ;

directAbstractDeclarator
    : LeftParen abstractDeclarator RightParen
    | LeftBracket typeQualifierList? assignmentExpression? RightBracket
    | LeftBracket Static typeQualifierList? assignmentExpression RightBracket
    | LeftBracket typeQualifierList Static assignmentExpression RightBracket
    | LeftBracket Star RightBracket
    | LeftParen parameterTypeList? RightParen
    | directAbstractDeclarator LeftBracket typeQualifierList? assignmentExpression? RightBracket
    | directAbstractDeclarator LeftBracket Static typeQualifierList? assignmentExpression RightBracket
    | directAbstractDeclarator LeftBracket typeQualifierList Static assignmentExpression RightBracket
    | directAbstractDeclarator LeftBracket Star RightBracket
    | directAbstractDeclarator LeftParen parameterTypeList? RightParen
    ;

typedefName
    : Identifier
    ;

initializer
    : assignmentExpression
    | LeftBrace initializerList Comma? RightBrace
    ;

initializerList
    : designation? initializer ( Comma designation? initializer )*
    ;

designation
    : designatorList Assign
    ;

designatorList
    : designator+
    ;

designator
    : LeftBracket constantExpression RightBracket
    | Dot Identifier
    ;

staticAssertDeclaration
    : StaticAssert LeftParen constantExpression Comma StringLiteral+ RightParen Semi
    ;

// ---------------------------------------------------------------------------
// Statements
// ---------------------------------------------------------------------------

statement
    : labeledStatement
    | compoundStatement
    | expressionStatement
    | selectionStatement
    | iterationStatement
    | jumpStatement
    ;

labeledStatement
    : Identifier Colon statement
    | Case constantExpression Colon statement
    | Default Colon statement
    ;

compoundStatement
    : LeftBrace blockItemList? RightBrace
    ;

blockItemList
    : blockItem+
    ;

blockItem
    : statement
    | declaration
    ;

expressionStatement
    : expression? Semi
    ;

selectionStatement
    : If LeftParen expression RightParen statement ( Else statement )?
    | Switch LeftParen expression RightParen statement
    ;

iterationStatement
    : While LeftParen expression RightParen statement
    | Do statement While LeftParen expression RightParen Semi
    | For LeftParen forCondition RightParen statement
    ;

forCondition
    : ( forDeclaration | expression? ) Semi forExpression? Semi forExpression?
    ;

forDeclaration
    : declarationSpecifiers initDeclaratorList?
    ;

forExpression
    : assignmentExpression ( Comma assignmentExpression )*
    ;

jumpStatement
    : Goto Identifier Semi
    | Continue Semi
    | Break Semi
    | Return expression? Semi
    ;

// ---------------------------------------------------------------------------
// Expressions
// ---------------------------------------------------------------------------

compilationUnit2
    : expression EOF
    ;

expression
    : assignmentExpression ( Comma assignmentExpression )*
    ;

assignmentExpression
    : conditionalExpression
    | unaryExpression assignmentOperator assignmentExpression
    ;

assignmentOperator
    : Assign | StarAssign | DivAssign | ModAssign | PlusAssign | MinusAssign
    | LeftShiftAssign | RightShiftAssign | AndAssign | XorAssign | OrAssign
    ;

conditionalExpression
    : logicalOrExpression ( Question expression Colon conditionalExpression )?
    ;

logicalOrExpression
    : logicalAndExpression ( OrOr logicalAndExpression )*
    ;

logicalAndExpression
    : inclusiveOrExpression ( AndAnd inclusiveOrExpression )*
    ;

inclusiveOrExpression
    : exclusiveOrExpression ( Or exclusiveOrExpression )*
    ;

exclusiveOrExpression
    : andExpression ( Caret andExpression )*
    ;

andExpression
    : equalityExpression ( And equalityExpression )*
    ;

equalityExpression
    : relationalExpression ( ( Equal | NotEqual ) relationalExpression )*
    ;

relationalExpression
    : shiftExpression ( ( Less | Greater | LessEqual | GreaterEqual ) shiftExpression )*
    ;

shiftExpression
    : additiveExpression ( ( LeftShift | RightShift ) additiveExpression )*
    ;

additiveExpression
    : multiplicativeExpression ( ( Plus | Minus ) multiplicativeExpression )*
    ;

multiplicativeExpression
    : castExpression ( ( Star | Div | Mod ) castExpression )*
    ;

castExpression
    : LeftParen typeName RightParen castExpression
    | unaryExpression
    ;

unaryExpression
    : postfixExpression
    | PlusPlus unaryExpression
    | MinusMinus unaryExpression
    | unaryOperator castExpression
    | Sizeof ( unaryExpression | LeftParen typeName RightParen )
    | Alignof LeftParen typeName RightParen
    | BuiltinVaArg LeftParen unaryExpression Comma typeName RightParen
    | BuiltinOffsetof LeftParen typeName Comma unaryExpression RightParen
    ;

unaryOperator
    : And | Star | Plus | Minus | Tilde | Not
    ;

// ---------------------------------------------------------------------------
// Postfix expressions — KEY RULE for detecting function calls
// ---------------------------------------------------------------------------

postfixExpression
    : primaryExpression
    | postfixExpression LeftBracket expression RightBracket          // array index
    | postfixExpression LeftParen argumentExpressionList? RightParen // FUNCTION CALL ← detect this
    | postfixExpression ( Dot | Arrow ) Identifier                   // member access
    | postfixExpression ( PlusPlus | MinusMinus )
    | LeftParen typeName RightParen LeftBrace initializerList Comma? RightBrace
    ;

argumentExpressionList
    : assignmentExpression ( Comma assignmentExpression )*
    ;

primaryExpression
    : Identifier
    | Constant
    | StringLiteral+
    | LeftParen expression RightParen
    | genericSelection
    ;

Constant
    : IntegerConstant
    | FloatingConstant
    | CharacterConstant
    ;

genericSelection
    : Generic LeftParen assignmentExpression Comma genericAssocList RightParen
    ;

genericAssocList
    : genericAssociation ( Comma genericAssociation )*
    ;

genericAssociation
    : ( typeName | Default ) Colon assignmentExpression
    ;

constantExpression
    : conditionalExpression
    ;
