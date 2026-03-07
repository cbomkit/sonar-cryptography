/*
 * Simplified C# Parser Grammar for Crypto Detection
 *
 * Handles parsing of C# source code sufficient for detecting
 * cryptographic API usage patterns. Focuses on:
 *   - Method invocations: Aes.Create(), RSA.Create(2048)
 *   - Constructor calls: new AesManaged(), new AesGcm(key)
 *   - Property assignments: aes.Mode = CipherMode.CBC
 *   - Variable/using declarations
 *
 * Simplified from the grammars-v4 C# grammar to minimize complexity
 * while correctly parsing the target patterns.
 */
parser grammar CSharpParser;

options { tokenVocab=CSharpLexer; }

// -----------------------------------------------
// Top level
// -----------------------------------------------
compilation_unit
    : extern_alias_directive*
      using_directive*
      global_attribute_section*
      namespace_member_declaration*
      EOF
    ;

extern_alias_directive
    : EXTERN 'alias' identifier SEMICOLON
    ;

using_directive
    : USING STATIC? (identifier ASSIGNMENT)? namespace_or_type_name SEMICOLON
    ;

global_attribute_section
    : OPEN_BRACKET (ASSEMBLY | MODULE) COLON attribute_list COMMA? CLOSE_BRACKET
    ;

// -----------------------------------------------
// Namespace and type declarations
// -----------------------------------------------
namespace_member_declaration
    : namespace_declaration
    | type_declaration
    ;

namespace_declaration
    : NAMESPACE qualified_identifier OPEN_BRACE
      extern_alias_directive*
      using_directive*
      namespace_member_declaration*
      CLOSE_BRACE SEMICOLON?
    ;

qualified_identifier
    : identifier (DOT identifier)*
    ;

type_declaration
    : all_member_modifier* (class_definition | struct_definition | interface_definition | enum_definition | delegate_definition)
    ;

// -----------------------------------------------
// Class / struct / interface
// -----------------------------------------------
class_definition
    : (RECORD CLASS? | CLASS) identifier type_parameter_list? class_base? type_parameter_constraints_clause*
      OPEN_BRACE class_member_declaration* CLOSE_BRACE SEMICOLON?
    ;

struct_definition
    : (RECORD STRUCT | STRUCT) identifier type_parameter_list? struct_interfaces? type_parameter_constraints_clause*
      OPEN_BRACE struct_member_declaration* CLOSE_BRACE SEMICOLON?
    ;

interface_definition
    : INTERFACE identifier type_parameter_list? interface_base? type_parameter_constraints_clause*
      OPEN_BRACE interface_member_declaration* CLOSE_BRACE SEMICOLON?
    ;

enum_definition
    : ENUM identifier (COLON base_type)? OPEN_BRACE enum_member_declaration (COMMA enum_member_declaration)* COMMA? CLOSE_BRACE SEMICOLON?
    ;

delegate_definition
    : DELEGATE return_type identifier type_parameter_list? OPEN_PARENS formal_parameter_list? CLOSE_PARENS type_parameter_constraints_clause* SEMICOLON
    ;

class_base
    : COLON class_type (COMMA namespace_or_type_name)*
    ;

struct_interfaces
    : COLON interface_type_list
    ;

interface_base
    : COLON interface_type_list
    ;

interface_type_list
    : namespace_or_type_name (COMMA namespace_or_type_name)*
    ;

type_parameter_list
    : LT type_parameter (COMMA type_parameter)* GT
    ;

type_parameter
    : attribute_section* identifier
    ;

type_parameter_constraints_clause
    : WHERE identifier COLON type_parameter_constraints_list
    ;

type_parameter_constraints_list
    : type_parameter_constraint (COMMA type_parameter_constraint)*
    ;

type_parameter_constraint
    : CLASS INTERR?
    | STRUCT
    | NOTNULL
    | UNMANAGED
    | NEW OPEN_PARENS CLOSE_PARENS
    | type_
    ;

// -----------------------------------------------
// Class members
// -----------------------------------------------
class_member_declaration
    : attribute_section*
      all_member_modifier*
      ( common_member_declaration
      | destructor_definition
      | type_declaration
      )
    ;

struct_member_declaration
    : attribute_section*
      all_member_modifier*
      ( common_member_declaration
      | type_declaration
      )
    ;

interface_member_declaration
    : attribute_section*
      NEW?
      ( interface_method_declaration
      | interface_property_declaration
      | interface_event_declaration
      | interface_indexer_declaration
      | interface_type_declaration
      )
    ;

enum_member_declaration
    : attribute_section* identifier (ASSIGNMENT expression)?
    ;

common_member_declaration
    : constant_declaration
    | typed_member_declaration
    | event_declaration
    | conversion_operator_declarator body
    | constructor_declaration
    | static_constructor_declaration
    ;

typed_member_declaration
    : (REF? type_ | VOID) (method_declaration | property_declaration | indexer_declaration | operator_declaration | field_declaration)
    ;

constant_declaration
    : CONST type_ constant_declarator (COMMA constant_declarator)* SEMICOLON
    ;

constant_declarator
    : identifier ASSIGNMENT expression
    ;

field_declaration
    : variable_declarator (COMMA variable_declarator)* SEMICOLON
    ;

method_declaration
    : method_member_name type_parameter_list? OPEN_PARENS formal_parameter_list? CLOSE_PARENS
      type_parameter_constraints_clause* method_body
    ;

method_member_name
    : (identifier | identifier DOUBLE_COLON identifier) (type_argument_list? DOT identifier)*
    ;

method_body
    : block
    | OP_LAMBDA throwable_expression SEMICOLON
    | SEMICOLON
    ;

property_declaration
    : member_name (accessor_declarations | OP_LAMBDA expression SEMICOLON)
    ;

member_name
    : namespace_or_type_name
    ;

accessor_declarations
    : (GET | SET | INIT | ADD | REMOVE) accessor_modifier? accessor_body (GET | SET | INIT | ADD | REMOVE) accessor_modifier? accessor_body
    | (GET | SET | INIT | ADD | REMOVE) accessor_modifier? accessor_body
    ;

accessor_modifier
    : PROTECTED INTERNAL | PRIVATE PROTECTED | INTERNAL PROTECTED | PROTECTED | INTERNAL | PRIVATE
    ;

accessor_body
    : block
    | OP_LAMBDA expression SEMICOLON
    | SEMICOLON
    ;

event_declaration
    : EVENT type_ (variable_declarator (COMMA variable_declarator)* SEMICOLON | member_name accessor_declarations)
    ;

indexer_declaration
    : THIS OPEN_BRACKET formal_parameter_list CLOSE_BRACKET accessor_declarations
    ;

operator_declaration
    : OPERATOR overloadable_operator OPEN_PARENS fixed_parameter (COMMA fixed_parameter)? CLOSE_PARENS body
    ;

overloadable_operator
    : PLUS | MINUS | BANG | TILDE | OP_INC | OP_DEC | TRUE | FALSE
    | STAR | DIV | PERCENT | AMP | BITWISE_OR | CARET | OP_LEFT_SHIFT | OP_RIGHT_SHIFT | OP_UNSIGNED_RIGHT_SHIFT
    | OP_EQ | OP_NE | LT | GT | OP_LE | OP_GE
    ;

conversion_operator_declarator
    : (IMPLICIT | EXPLICIT) OPERATOR type_ OPEN_PARENS type_ identifier CLOSE_PARENS
    ;

constructor_declaration
    : identifier OPEN_PARENS formal_parameter_list? CLOSE_PARENS constructor_initializer? body
    ;

constructor_initializer
    : COLON (BASE | THIS) OPEN_PARENS argument_list? CLOSE_PARENS
    ;

static_constructor_declaration
    : STATIC identifier OPEN_PARENS CLOSE_PARENS static_constructor_body
    ;

static_constructor_body
    : block | SEMICOLON
    ;

destructor_definition
    : TILDE identifier OPEN_PARENS CLOSE_PARENS body
    ;

interface_method_declaration
    : return_type identifier type_parameter_list? OPEN_PARENS formal_parameter_list? CLOSE_PARENS
      type_parameter_constraints_clause* SEMICOLON
    ;

interface_property_declaration
    : type_ identifier OPEN_BRACE interface_accessors CLOSE_BRACE
    ;

interface_accessors
    : (GET | SET | INIT) SEMICOLON ((GET | SET | INIT) SEMICOLON)?
    ;

interface_event_declaration
    : EVENT type_ identifier SEMICOLON
    ;

interface_indexer_declaration
    : type_ THIS OPEN_BRACKET formal_parameter_list CLOSE_BRACKET OPEN_BRACE interface_accessors CLOSE_BRACE
    ;

interface_type_declaration
    : type_declaration
    ;

body
    : block
    | OP_LAMBDA expression SEMICOLON
    | SEMICOLON
    ;

// -----------------------------------------------
// Parameters
// -----------------------------------------------
formal_parameter_list
    : fixed_parameters (COMMA parameter_array)?
    | parameter_array
    ;

fixed_parameters
    : fixed_parameter (COMMA fixed_parameter)*
    ;

fixed_parameter
    : attribute_section* parameter_modifier? arg_declaration
    ;

parameter_modifier
    : REF | OUT | IN | PARAMS | THIS | REF THIS | IN THIS
    ;

parameter_array
    : attribute_section* PARAMS array_type identifier
    ;

arg_declaration
    : type_ identifier (ASSIGNMENT expression)?
    ;

// -----------------------------------------------
// Types
// -----------------------------------------------
return_type
    : type_ | VOID
    ;

type_
    : base_type (INTERR | rank_specifier | STAR)*
    ;

base_type
    : simple_type
    | class_type
    | VOID STAR
    | tuple_type
    ;

tuple_type
    : OPEN_PARENS tuple_element (COMMA tuple_element)+ CLOSE_PARENS
    ;

tuple_element
    : type_ identifier?
    ;

simple_type
    : numeric_type | BOOL
    ;

numeric_type
    : integral_type | floating_point_type | DECIMAL_KW
    ;

integral_type
    : SBYTE | BYTE | SHORT_KW | USHORT | INT_KW | UINT | LONG_KW | ULONG | CHAR
    ;

floating_point_type
    : FLOAT_KW | DOUBLE_KW
    ;

class_type
    : namespace_or_type_name
    | OBJECT_KW
    | DYNAMIC
    | STRING_KW
    ;

array_type
    : base_type rank_specifier+
    ;

rank_specifier
    : OPEN_BRACKET COMMA* CLOSE_BRACKET
    ;

namespace_or_type_name
    : identifier type_argument_list?
      (DOT identifier type_argument_list? | DOUBLE_COLON identifier type_argument_list?)*
    ;

type_argument_list
    : LT type_ (COMMA type_)* GT
    ;

base_type_for_inherit
    : namespace_or_type_name | class_type
    ;

class_type_for_inherit
    : namespace_or_type_name
    ;

// -----------------------------------------------
// Attributes
// -----------------------------------------------
attribute_section
    : OPEN_BRACKET (attribute_target COLON)? attribute_list COMMA? CLOSE_BRACKET
    ;

attribute_target
    : keyword
    | identifier
    ;

attribute_list
    : attribute_ (COMMA attribute_)*
    ;

attribute_
    : namespace_or_type_name (OPEN_PARENS attribute_argument (COMMA attribute_argument)* CLOSE_PARENS)?
    ;

attribute_argument
    : (identifier COLON)? expression
    ;

// -----------------------------------------------
// Statements
// -----------------------------------------------
block
    : OPEN_BRACE statement_list? CLOSE_BRACE
    ;

statement_list
    : statement+
    ;

statement
    : labeled_statement
    | declaration_statement
    | embedded_statement
    ;

labeled_statement
    : identifier COLON statement
    ;

declaration_statement
    : local_variable_declaration SEMICOLON
    | local_constant_declaration SEMICOLON
    | local_function_declaration
    ;

local_variable_declaration
    : (USING? local_variable_type local_variable_declarator (COMMA local_variable_declarator)*)
    | ref_local_variable_declaration
    ;

ref_local_variable_declaration
    : REF type_ identifier ASSIGNMENT REF expression
    ;

local_variable_type
    : VAR
    | type_
    ;

local_variable_declarator
    : identifier (ASSIGNMENT ref_variable_initial? local_variable_initializer)?
    ;

ref_variable_initial
    : REF READONLY?
    ;

local_variable_initializer
    : expression
    | array_initializer
    ;

local_constant_declaration
    : CONST type_ constant_declarator (COMMA constant_declarator)*
    ;

local_function_declaration
    : local_function_modifier* return_type identifier type_parameter_list?
      OPEN_PARENS formal_parameter_list? CLOSE_PARENS type_parameter_constraints_clause* body
    ;

local_function_modifier
    : ASYNC | UNSAFE | STATIC
    ;

embedded_statement
    : block
    | simple_embedded_statement
    ;

simple_embedded_statement
    : SEMICOLON                                             #theEmptyStatement
    | expression SEMICOLON                                  #expressionStatement
    | IF OPEN_PARENS expression CLOSE_PARENS embedded_statement (ELSE embedded_statement)?    #ifStatement
    | SWITCH OPEN_PARENS expression CLOSE_PARENS OPEN_BRACE switch_section* CLOSE_BRACE       #switchStatement
    | WHILE OPEN_PARENS expression CLOSE_PARENS embedded_statement                            #whileStatement
    | DO embedded_statement WHILE OPEN_PARENS expression CLOSE_PARENS SEMICOLON               #doStatement
    | FOR OPEN_PARENS for_initializer? SEMICOLON expression? SEMICOLON for_iterator? CLOSE_PARENS embedded_statement  #forStatement
    | FOREACH OPEN_PARENS (VAR | type_) identifier IN expression CLOSE_PARENS embedded_statement  #foreachStatement
    | BREAK SEMICOLON                                       #breakStatement
    | CONTINUE SEMICOLON                                    #continueStatement
    | GOTO (identifier | CASE expression | DEFAULT) SEMICOLON  #gotoStatement
    | RETURN expression? SEMICOLON                          #returnStatement
    | THROW expression? SEMICOLON                           #throwStatement
    | TRY block (catch_clauses finally_clause? | finally_clause)   #tryStatement
    | CHECKED block                                         #checkedStatement
    | UNCHECKED block                                       #uncheckedStatement
    | LOCK OPEN_PARENS expression CLOSE_PARENS embedded_statement  #lockStatement
    | USING OPEN_PARENS resource_acquisition CLOSE_PARENS embedded_statement  #usingStatement
    | YIELD (RETURN expression | BREAK) SEMICOLON           #yieldStatement
    | UNSAFE block                                          #unsafeStatement
    | FIXED OPEN_PARENS pointer_type fixed_pointer_declarators CLOSE_PARENS embedded_statement  #fixedStatement
    ;

for_initializer
    : local_variable_declaration
    | expression (COMMA expression)*
    ;

for_iterator
    : expression (COMMA expression)*
    ;

switch_section
    : switch_label+ statement_list
    ;

switch_label
    : CASE expression COLON
    | DEFAULT COLON
    ;

catch_clauses
    : specific_catch_clause+ general_catch_clause?
    | general_catch_clause
    ;

specific_catch_clause
    : CATCH OPEN_PARENS class_type identifier? CLOSE_PARENS exception_filter? block
    ;

general_catch_clause
    : CATCH exception_filter? block
    ;

exception_filter
    : WHEN OPEN_PARENS expression CLOSE_PARENS
    ;

finally_clause
    : FINALLY block
    ;

resource_acquisition
    : local_variable_declaration
    | expression
    ;

pointer_type
    : simple_type STAR
    | class_type STAR
    | VOID STAR
    ;

fixed_pointer_declarators
    : fixed_pointer_declarator (COMMA fixed_pointer_declarator)*
    ;

fixed_pointer_declarator
    : identifier ASSIGNMENT fixed_pointer_initializer
    ;

fixed_pointer_initializer
    : AMP expression
    | expression
    ;

// -----------------------------------------------
// Expressions
// -----------------------------------------------
throwable_expression
    : expression
    | throw_expression
    ;

throw_expression
    : THROW expression
    ;

expression
    : assignment
    | non_assignment_expression
    | REF non_assignment_expression
    ;

non_assignment_expression
    : lambda_expression
    | query_expression
    | conditional_expression
    ;

assignment
    : unary_expression assignment_operator expression
    | unary_expression OP_COALESCING ASSIGNMENT expression
    ;

assignment_operator
    : ASSIGNMENT | OP_ADD_ASSIGNMENT | OP_SUB_ASSIGNMENT | OP_MULT_ASSIGNMENT | OP_DIV_ASSIGNMENT
    | OP_MOD_ASSIGNMENT | OP_AND_ASSIGNMENT | OP_OR_ASSIGNMENT | OP_XOR_ASSIGNMENT
    | OP_LEFT_SHIFT_ASSIGNMENT | OP_RIGHT_SHIFT_ASSIGNMENT | OP_UNSIGNED_RIGHT_SHIFT_ASSIGNMENT
    ;

conditional_expression
    : null_coalescing_expression (INTERR throwable_expression COLON throwable_expression)?
    ;

null_coalescing_expression
    : conditional_or_expression (OP_COALESCING (null_coalescing_expression | throw_expression))?
    ;

conditional_or_expression
    : conditional_and_expression (OP_OR conditional_and_expression)*
    ;

conditional_and_expression
    : inclusive_or_expression (OP_AND inclusive_or_expression)*
    ;

inclusive_or_expression
    : exclusive_or_expression (BITWISE_OR exclusive_or_expression)*
    ;

exclusive_or_expression
    : and_expression (CARET and_expression)*
    ;

and_expression
    : equality_expression (AMP equality_expression)*
    ;

equality_expression
    : relational_expression ((OP_EQ | OP_NE) relational_expression)*
    ;

relational_expression
    : shift_expression ((LT | GT | OP_LE | OP_GE) shift_expression | IS isType | AS type_)*
    ;

isType
    : base_type (rank_specifier | STAR)* INTERR? identifier?
    | VAR identifier
    | type_ identifier?
    ;

shift_expression
    : additive_expression ((OP_LEFT_SHIFT | OP_RIGHT_SHIFT | OP_UNSIGNED_RIGHT_SHIFT) additive_expression)*
    ;

additive_expression
    : multiplicative_expression ((PLUS | MINUS) multiplicative_expression)*
    ;

multiplicative_expression
    : switch_expression ((STAR | DIV | PERCENT) switch_expression)*
    ;

switch_expression
    : range_expression (SWITCH OPEN_BRACE (switch_expression_arm (COMMA switch_expression_arm)* COMMA?)? CLOSE_BRACE)?
    ;

switch_expression_arm
    : expression case_guard? OP_LAMBDA throwable_expression
    ;

case_guard
    : WHEN expression
    ;

range_expression
    : unary_expression
    | unary_expression? OP_RANGE unary_expression?
    ;

unary_expression
    : PLUS unary_expression
    | MINUS unary_expression
    | BANG unary_expression
    | TILDE unary_expression
    | OP_INC unary_expression
    | OP_DEC unary_expression
    | OPEN_PARENS type_ CLOSE_PARENS unary_expression
    | AWAIT unary_expression
    | AMP unary_expression
    | STAR unary_expression
    | primary_expression
    ;

primary_expression
    : pe=primary_expression_start bracket_expression* (
        (member_access | method_invocation | OP_INC | OP_DEC | OP_NULL_DOT | OP_NULL_BRACKET argument_list CLOSE_BRACKET) bracket_expression* )*
    ;

// The core expression start (literals, identifiers, etc.)
primary_expression_start
    : literal                               #literalExpression
    | identifier type_argument_list?        #simpleNameExpression
    | OPEN_PARENS expression CLOSE_PARENS   #parenthesizedExpression
    | THIS                                  #thisReferenceExpression
    | BASE (DOT identifier type_argument_list? | OPEN_BRACKET expression_list CLOSE_BRACKET)  #baseAccessExpression
    | NEW (object_creation_expression | object_or_collection_initializer | anonymous_object_creation | array_creation_expression | stackalloc_initializer)  #objectCreationExpression
    | TYPEOF OPEN_PARENS (unbound_type_name | VOID) CLOSE_PARENS   #typeofExpression
    | CHECKED OPEN_PARENS expression CLOSE_PARENS                   #checkedExpression
    | UNCHECKED OPEN_PARENS expression CLOSE_PARENS                 #uncheckedExpression
    | DEFAULT (OPEN_PARENS type_ CLOSE_PARENS)?                    #defaultValueExpression
    | THROW expression                                              #throwExpression
    | SIZEOF OPEN_PARENS type_ CLOSE_PARENS                        #sizeofExpression
    | NAMEOF OPEN_PARENS (identifier DOT)* identifier CLOSE_PARENS #nameofExpression
    ;

member_access
    : INTERR? DOT identifier type_argument_list?
    ;

method_invocation
    : OPEN_PARENS argument_list? CLOSE_PARENS
    ;


object_creation_expression
    : type_ (object_creation_args object_or_collection_initializer?
            | object_or_collection_initializer)
    ;

object_creation_args
    : OPEN_PARENS argument_list? CLOSE_PARENS
    ;

object_or_collection_initializer
    : object_initializer
    | collection_initializer
    ;

object_initializer
    : OPEN_BRACE (member_initializer_list COMMA?)? CLOSE_BRACE
    ;

member_initializer_list
    : member_initializer (COMMA member_initializer)*
    ;

member_initializer
    : (identifier | OPEN_BRACKET expression CLOSE_BRACKET) ASSIGNMENT initializer_value
    ;

initializer_value
    : expression
    | object_or_collection_initializer
    ;

collection_initializer
    : OPEN_BRACE element_initializer (COMMA element_initializer)* COMMA? CLOSE_BRACE
    ;

element_initializer
    : non_assignment_expression
    | OPEN_BRACE expression_list CLOSE_BRACE
    ;

anonymous_object_creation
    : OPEN_BRACE (member_declarator (COMMA member_declarator)* COMMA?)? CLOSE_BRACE
    ;

member_declarator
    : primary_expression
    | identifier ASSIGNMENT expression
    ;

unbound_type_name
    : identifier DOUBLE_COLON? generic_dimension_specifier?
      (DOT identifier generic_dimension_specifier?)*
    ;

generic_dimension_specifier
    : LT COMMA* GT
    ;

array_creation_expression
    : non_array_type OPEN_BRACKET expression_list CLOSE_BRACKET rank_specifier* array_initializer?
    | array_type array_initializer
    | rank_specifier array_initializer
    ;

non_array_type
    : type_
    ;

stackalloc_initializer
    : STACKALLOC type_ OPEN_BRACKET expression? CLOSE_BRACKET (array_initializer | OPEN_BRACKET expression CLOSE_BRACKET)?
    ;

bracket_expression
    : OPEN_BRACKET indexer_argument (COMMA indexer_argument)* CLOSE_BRACKET
    ;

indexer_argument
    : (identifier COLON)? expression
    ;

expression_list
    : expression (COMMA expression)*
    ;

// -----------------------------------------------
// Argument lists
// -----------------------------------------------
argument_list
    : argument (COMMA argument)*
    ;

argument
    : (identifier COLON)? refout_keyword? expression
    | (identifier COLON)? refout_keyword? VAR identifier
    ;

refout_keyword
    : REF | OUT | IN
    ;

// -----------------------------------------------
// Lambda expressions
// -----------------------------------------------
lambda_expression
    : ASYNC? anonymous_function_signature OP_LAMBDA anonymous_function_body
    ;

anonymous_function_signature
    : OPEN_PARENS CLOSE_PARENS
    | OPEN_PARENS explicit_anonymous_function_parameter_list CLOSE_PARENS
    | OPEN_PARENS implicit_anonymous_function_parameter_list CLOSE_PARENS
    | identifier
    ;

explicit_anonymous_function_parameter_list
    : explicit_anonymous_function_parameter (COMMA explicit_anonymous_function_parameter)*
    ;

explicit_anonymous_function_parameter
    : parameter_modifier? type_ identifier
    ;

implicit_anonymous_function_parameter_list
    : identifier (COMMA identifier)*
    ;

anonymous_function_body
    : throwable_expression
    | block
    ;

// -----------------------------------------------
// Query expressions (simplified)
// -----------------------------------------------
query_expression
    : FROM (type_ | VAR)? identifier IN expression query_body
    ;

query_body
    : query_body_clause* select_or_group_clause query_continuation?
    ;

query_body_clause
    : from_clause | let_clause | where_clause | join_clause | orderby_clause
    ;

from_clause
    : FROM (type_ | VAR)? identifier IN expression
    ;

let_clause
    : LET identifier ASSIGNMENT expression
    ;

where_clause
    : WHERE expression
    ;

join_clause
    : JOIN (type_ | VAR)? identifier IN expression ON expression EQUALS expression (INTO identifier)?
    ;

orderby_clause
    : ORDERBY ordering (COMMA ordering)*
    ;

ordering
    : expression (ASCENDING | DESCENDING)?
    ;

select_or_group_clause
    : SELECT expression
    | GROUP expression BY expression
    ;

query_continuation
    : INTO identifier query_body
    ;

// -----------------------------------------------
// Array initializer
// -----------------------------------------------
array_initializer
    : OPEN_BRACE (variable_initializer_list COMMA?)? CLOSE_BRACE
    ;

variable_initializer_list
    : variable_initializer (COMMA variable_initializer)*
    ;

variable_initializer
    : expression | array_initializer
    ;

// -----------------------------------------------
// Variable declarators
// -----------------------------------------------
variable_declarator
    : identifier (ASSIGNMENT variable_initializer)?
    ;

// -----------------------------------------------
// Identifiers and keywords as identifiers
// -----------------------------------------------
identifier
    : IDENTIFIER
    | ADD | ALIAS | ASCENDING | ASYNC | BY | DESCENDING | DYNAMIC | EQUALS
    | FROM | GET | GLOBAL | GROUP | INTO | JOIN | LET | NAMEOF | NOT
    | ON | OR | AND | ORDERBY | PARTIAL | RECORD | REMOVE | SELECT
    | SET | UNMANAGED | VAR | WHEN | WHERE | WITH | YIELD
    | INIT | REQUIRED | FILE
    ;

keyword
    : ABSTRACT | AS | BASE | BOOL | BREAK | BYTE | CASE | CATCH | CHAR | CHECKED
    | CLASS | CONST | CONTINUE | DECIMAL_KW | DEFAULT | DELEGATE | DO | DOUBLE_KW
    | ELSE | ENUM | EVENT | EXPLICIT | EXTERN | FALSE | FINALLY | FIXED | FLOAT_KW
    | FOR | FOREACH | GOTO | IF | IMPLICIT | IN | INT_KW | INTERFACE | INTERNAL
    | IS | LOCK | LONG_KW | NAMESPACE | NEW | NULL | OBJECT_KW | OPERATOR | OUT
    | OVERRIDE | PARAMS | PRIVATE | PROTECTED | PUBLIC | READONLY | REF | RETURN
    | SBYTE | SEALED | SHORT_KW | SIZEOF | STACKALLOC | STATIC | STRING_KW | STRUCT
    | SWITCH | THIS | THROW | TRUE | TRY | TYPEOF | UINT | ULONG | UNCHECKED
    | UNSAFE | USHORT | USING | VIRTUAL | VOID | VOLATILE | WHILE
    ;

literal
    : boolean_literal
    | string_literal
    | INTEGER_LITERAL
    | REAL_LITERAL
    | CHARACTER_LITERAL
    | NULL
    ;

boolean_literal
    : TRUE | FALSE
    ;

string_literal
    : REGULAR_STRING
    | VERBATIM_STRING
    | INTERPOLATED_REGULAR_STRING
    | INTERPOLATED_VERBATIM_STRING
    ;

all_member_modifier
    : NEW | PUBLIC | PROTECTED | INTERNAL | PRIVATE | READONLY | VIRTUAL | SEALED
    | OVERRIDE | ABSTRACT | STATIC | UNSAFE | EXTERN | PARTIAL | ASYNC | VOLATILE
    | REQUIRED | FILE
    ;
