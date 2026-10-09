/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2024 PQCA
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.ibm.engine.language.csharp;

import com.ibm.engine.language.csharp.antlr.CSharpParser;
import com.ibm.engine.language.csharp.antlr.CSharpParserBaseVisitor;
import com.ibm.engine.language.csharp.tree.CSharpArgument;
import com.ibm.engine.language.csharp.tree.CSharpArrayCreationTree;
import com.ibm.engine.language.csharp.tree.CSharpBinaryExpressionTree;
import com.ibm.engine.language.csharp.tree.CSharpBlockTree;
import com.ibm.engine.language.csharp.tree.CSharpIdentifierTree;
import com.ibm.engine.language.csharp.tree.CSharpLiteralTree;
import com.ibm.engine.language.csharp.tree.CSharpMemberAccessTree;
import com.ibm.engine.language.csharp.tree.CSharpMethodInvocationTree;
import com.ibm.engine.language.csharp.tree.CSharpObjectCreationTree;
import com.ibm.engine.language.csharp.tree.CSharpScope;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.language.csharp.tree.CSharpUnknownTree;
import com.ibm.engine.language.csharp.tree.CSharpVariable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.antlr.v4.runtime.Token;
import org.antlr.v4.runtime.tree.ParseTree;

/**
 * Converts an ANTLR4 C# parse tree to the language-agnostic {@link CSharpTree} hierarchy.
 *
 * <p>This visitor walks the whole compilation unit and extracts one {@link CSharpBlockTree} per
 * top-level scope (a method/constructor/accessor/operator body, or a lambda/local-function body),
 * each carrying a {@link CSharpScope} symbol table populated with the locals, {@code const}s and
 * parameters visible in it (see {@link #buildClassConstScope}, {@link #defineParameters}, and
 * {@code StatementCollector}'s declaration handling).
 *
 * <p><b>Block flattening:</b> unlike a real compiler, this converter deliberately does <em>not</em>
 * create a separate {@link CSharpBlockTree} for every {@code { }} scope. Nested control-flow blocks
 * ({@code if}/{@code for}/{@code while}/{@code foreach}/{@code using}/{@code lock}/{@code
 * fixed}/{@code try}/{@code catch}/{@code finally}/{@code checked}/{@code unchecked}/{@code
 * unsafe}, and a bare nested {@code { }}) are flattened into the enclosing top-level block's
 * statement list, in a nested {@link CSharpScope} — see {@code
 * StatementCollector#isFlattenedControlFlowBlock}. This is what lets a detection rule track a
 * variable across e.g. {@code using (var aes = Aes.Create()) { aes.Mode = CipherMode.CBC; }}: both
 * statements land in the same {@code CSharpBlockTree}. Only lambda bodies and local-function bodies
 * become their own independent top-level {@code CSharpBlockTree}, chained to the scope active where
 * they were declared.
 *
 * <p><b>Resolution reach.</b> Beyond the lexical scope chain, the converter runs two passes over
 * the finished compilation unit so that values which are only knowable file-wide still resolve:
 * {@link #resolveParametersFromCallSites()} gives a formal parameter the value its callers pass
 * when every call site in the file agrees on one, and {@link #resolveLocalCallReturnValues()} gives
 * a call to a method of this file the value that method returns when it has exactly one. Both are
 * deliberately all-or-nothing — one disagreeing call site or a second return value leaves the value
 * unknown.
 *
 * <p><b>Known gaps</b> (kept narrow on purpose, consistent with "no value is better than a wrong
 * one"):
 *
 * <ul>
 *   <li>Nothing resolves across file boundaries: a parameter fed only from another file, or a call
 *       into another type, has no value here.
 *   <li>A class-level field is only resolved when it has an initializer and the same class never
 *       assigns to it; a field written through a property setter or from another class is treated
 *       as unknown.
 *   <li>Values that require evaluating control flow stay unknown by design: a ternary or {@code
 *       switch} expression with differing branches, an element access ({@code sizes[0]}), a {@code
 *       ??} fallback. The argument still occupies its position (see {@code CSharpUnknownTree}), so
 *       the surrounding algorithm is detected — only its parameter is missing.
 *   <li>An object initializer is modelled as property setters only when the created object is
 *       assigned to a variable; a {@code new T { ... }} passed straight into another call has no
 *       receiver name to attach them to.
 *   <li>A chained call reports the chain's root type as the receiver, which is right for the .NET
 *       {@code X.Create() -> X} factory convention but would be wrong for a chain that changes type
 *       (e.g. a fluent builder returning a different class).
 * </ul>
 */
public final class CSharpTreeConverter {

    private final List<CSharpBlockTree> bodies = new ArrayList<>();

    /**
     * Statement list currently being collected, used by {@link #convertCallChain} to emit the inner
     * calls of a chained expression as statements of their own. Saved and restored around every
     * body so a nested lambda body cannot steal the enclosing body's sink.
     */
    @Nullable private List<CSharpTree> chainCallSink;

    /**
     * Argument lists of every call in this file made without a receiver, or on {@code this} — i.e.
     * every call that can only be to a method of the enclosing type, keyed by method name. Filled
     * while converting and consumed afterwards by {@link #resolveParametersFromCallSites()}.
     */
    @Nonnull private final Map<String, List<List<CSharpArgument>>> localCallSites = new HashMap<>();

    /**
     * The single expression each local method returns, keyed by method name — from an expression
     * body ({@code int Foo() => 2048;}) or from a block body whose only statement is a {@code
     * return}. A method with several returns is registered as absent, so it resolves to nothing.
     */
    @Nonnull private final Map<String, CSharpTree> localMethodReturns = new HashMap<>();

    /** Method names seen with more than one return, which therefore have no single value. */
    @Nonnull private final Set<String> ambiguousMethodReturns = new HashSet<>();

    /** Calls to a method of the enclosing type, awaiting that method's return value. */
    @Nonnull
    private final List<Map.Entry<String, CSharpMethodInvocationTree>> localCalls =
            new ArrayList<>();

    /** Parameters awaiting a value from their method's call sites (see the same method). */
    @Nonnull private final List<PendingParameter> pendingParameters = new ArrayList<>();

    /** A formal parameter and where it would have to be resolved from. */
    private record PendingParameter(
            @Nonnull CSharpScope scope,
            @Nonnull String name,
            @Nonnull String declaringMethod,
            int index) {}

    /**
     * Extracts all top-level scopes from the compilation unit.
     *
     * @param root the root parse tree node
     * @return list of block trees, one per
     *     method/constructor/accessor/operator/lambda/local-function body found (plus one synthetic
     *     block for C# 9+ top-level statements, if present)
     */
    @Nonnull
    public List<CSharpBlockTree> extractMethodBodies(
            @Nonnull CSharpParser.Compilation_unitContext root) {
        walk(root, null);
        resolveParametersFromCallSites();
        resolveLocalCallReturnValues();
        if (root.statement() != null && !root.statement().isEmpty()) {
            // C# 9+ top-level statements (a `Program.cs` with no explicit Main method) — treat the
            // whole file as one synthetic method body so top-level crypto calls are still found.
            CSharpScope topLevelScope = new CSharpScope(null);
            StatementCollector collector = new StatementCollector(topLevelScope);
            List<CSharpTree> previousSink = chainCallSink;
            chainCallSink = collector.mutableStatements();
            try {
                for (CSharpParser.StatementContext statement : root.statement()) {
                    collector.visit(statement);
                }
            } finally {
                chainCallSink = previousSink;
            }
            bodies.add(
                    new CSharpBlockTree(
                            root.getStart().getLine(),
                            root.getStart().getCharPositionInLine(),
                            collector.getStatements(),
                            topLevelScope));
        }
        return Collections.unmodifiableList(bodies);
    }

    // -------------------------------------------------------------------------
    // Outer structural walk: finds class/record scopes and top-level bodies
    // -------------------------------------------------------------------------

    /**
     * Recursively walks the parse tree looking for class/record definitions (to build a {@code
     * const}-scope, see {@link #buildClassConstScope}) and method/constructor bodies (to register
     * formal parameters before handing the block to {@link #processTopLevelBody}). Any other
     * top-level scope-owning block reached generically (property/indexer/operator/event accessors,
     * destructors, anonymous methods) still gets picked up by the final {@code BlockContext}
     * fallback below, just without its own parameters pre-registered.
     */
    private void walk(@Nonnull ParseTree node, @Nullable CSharpScope scope) {
        if (node instanceof CSharpParser.Class_definitionContext classCtx) {
            CSharpScope classScope = buildClassConstScope(classCtx.class_body(), scope);
            walkChildren(classCtx, classScope);
            return;
        }
        if (node instanceof CSharpParser.Record_definitionContext recordCtx
                && recordCtx.record_body() != null
                && recordCtx.record_body().class_body() != null) {
            CSharpScope classScope =
                    buildClassConstScope(recordCtx.record_body().class_body(), scope);
            walkChildren(recordCtx, classScope);
            return;
        }
        if (node instanceof CSharpParser.Method_declarationContext methodCtx) {
            CSharpScope bodyScope = new CSharpScope(scope);
            defineParameters(
                    methodCtx.formal_parameter_list(),
                    bodyScope,
                    simpleMethodName(methodCtx.method_member_name()));
            String methodName = simpleMethodName(methodCtx.method_member_name());
            CSharpParser.Method_bodyContext body = methodCtx.method_body();
            if (body != null && body.block() != null) {
                recordMethodReturn(methodName, body.block(), bodyScope);
                processTopLevelBody(body.block(), bodyScope);
            } else {
                // Expression-bodied method: `int Foo() => Bar(2048);`
                CSharpParser.Throwable_expressionContext arrow = methodCtx.throwable_expression();
                if (methodName != null && arrow != null && arrow.expression() != null) {
                    registerMethodReturn(
                            methodName, convertExpression(arrow.expression(), bodyScope));
                }
                processExpressionBody(arrow, bodyScope);
            }
            return;
        }
        if (node instanceof CSharpParser.Constructor_declarationContext ctorCtx) {
            CSharpParser.BodyContext body = ctorCtx.body();
            if (body != null && body.block() != null) {
                CSharpScope bodyScope = new CSharpScope(scope);
                // A constructor's parameters are not resolved from call sites: `new T(...)`
                // is not recorded as a local call (it has a receiver type, not a bare name).
                defineParameters(ctorCtx.formal_parameter_list(), bodyScope, null);
                processTopLevelBody(body.block(), bodyScope);
            }
            return;
        }
        if (node instanceof CSharpParser.Throwable_expressionContext arrowBody) {
            // Any other expression-bodied member reached generically: a property, an indexer, an
            // operator or a conversion operator written with `=>`. Their crypto calls are just as
            // detectable as a block body's, and a property getter in particular is a very common
            // place for `=> SHA256.Create()`-style code.
            processExpressionBody(arrowBody, new CSharpScope(scope));
            return;
        }
        if (node instanceof CSharpParser.BlockContext blockCtx) {
            processTopLevelBody(blockCtx, new CSharpScope(scope));
            return;
        }
        walkChildren(node, scope);
    }

    private void walkChildren(@Nonnull ParseTree node, @Nullable CSharpScope scope) {
        for (int i = 0; i < node.getChildCount(); i++) {
            walk(node.getChild(i), scope);
        }
    }

    /**
     * Runs a {@link StatementCollector} over one top-level block and records the resulting {@link
     * CSharpBlockTree}. {@code bodyScope} must already contain this body's formal parameters, if
     * any (see {@link #defineParameters}) — this method only collects statements, it does not
     * allocate a fresh child scope itself.
     */
    private void processTopLevelBody(
            @Nonnull CSharpParser.BlockContext block, @Nonnull CSharpScope bodyScope) {
        StatementCollector collector = new StatementCollector(bodyScope);
        CSharpParser.Statement_listContext statementList = block.statement_list();
        List<CSharpTree> previousSink = chainCallSink;
        chainCallSink = collector.mutableStatements();
        try {
            if (statementList != null) {
                for (CSharpParser.StatementContext statement : statementList.statement()) {
                    collector.visit(statement);
                }
            }
        } finally {
            chainCallSink = previousSink;
        }
        bodies.add(
                new CSharpBlockTree(
                        block.getStart().getLine(),
                        block.getStart().getCharPositionInLine(),
                        collector.getStatements(),
                        bodyScope));
    }

    /**
     * Converts an expression-bodied member ({@code => expression}) into a {@link CSharpBlockTree},
     * so that its calls are detected exactly like a block body's and its call sites are recorded
     * for {@link #resolveParametersFromCallSites()}.
     */
    private void processExpressionBody(
            @Nullable CSharpParser.Throwable_expressionContext arrowBody,
            @Nonnull CSharpScope bodyScope) {
        if (arrowBody == null || arrowBody.expression() == null) {
            return;
        }
        List<CSharpTree> statements = new ArrayList<>();
        List<CSharpTree> previousSink = chainCallSink;
        chainCallSink = statements;
        try {
            CSharpTree value = convertExpression(arrowBody.expression(), bodyScope);
            if (isStatementWorthy(value)) {
                statements.add(value);
            }
        } finally {
            chainCallSink = previousSink;
        }
        if (statements.isEmpty()) {
            return;
        }
        bodies.add(
                new CSharpBlockTree(
                        arrowBody.getStart().getLine(),
                        arrowBody.getStart().getCharPositionInLine(),
                        Collections.unmodifiableList(statements),
                        bodyScope));
    }

    /** Registers a method/constructor/local-function's formal parameters in {@code scope}. */
    private void defineParameters(
            @Nullable CSharpParser.Formal_parameter_listContext params,
            @Nonnull CSharpScope scope,
            @Nullable String declaringMethod) {
        if (params == null || params.fixed_parameters() == null) {
            return;
        }
        int index = 0;
        for (CSharpParser.Fixed_parameterContext parameter :
                params.fixed_parameters().fixed_parameter()) {
            CSharpParser.Arg_declarationContext decl = parameter.arg_declaration();
            if (decl == null || decl.identifier() == null) {
                index++;
                continue;
            }
            String name = decl.identifier().getText();
            String declaredType = decl.type_() != null ? decl.type_().getText() : null;
            scope.define(
                    name,
                    new CSharpVariable(
                            name,
                            declaredType,
                            null,
                            0,
                            CSharpVariable.Kind.PARAMETER,
                            decl.getStart().getLine()));
            if (declaringMethod != null) {
                pendingParameters.add(new PendingParameter(scope, name, declaringMethod, index));
            }
            index++;
        }
    }

    /**
     * Records the value a block-bodied method returns, when its body is a single {@code return
     * <expression>;} — the shape of the small helper methods that production code uses to hand a
     * key size or an algorithm name to a crypto call ({@code int KeySize() { return 2048; }}).
     */
    private void recordMethodReturn(
            @Nullable String methodName,
            @Nonnull CSharpParser.BlockContext block,
            @Nonnull CSharpScope bodyScope) {
        if (methodName == null || block.statement_list() == null) {
            return;
        }
        List<CSharpParser.StatementContext> statements = block.statement_list().statement();
        if (statements.size() != 1) {
            // Not a single-statement body: either no return at all, or control flow we do not
            // evaluate. Mark ambiguous so a second, simpler overload cannot supply a wrong value.
            ambiguousMethodReturns.add(methodName);
            return;
        }
        CSharpParser.ReturnStatementContext returnStatement =
                findReturnStatement(statements.get(0));
        if (returnStatement == null || returnStatement.expression() == null) {
            ambiguousMethodReturns.add(methodName);
            return;
        }
        registerMethodReturn(
                methodName, convertExpression(returnStatement.expression(), bodyScope));
    }

    /**
     * Registers a method's return value, marking it ambiguous if a different one is already known.
     */
    private void registerMethodReturn(@Nonnull String methodName, @Nullable CSharpTree value) {
        if (value == null) {
            ambiguousMethodReturns.add(methodName);
            return;
        }
        CSharpTree known = localMethodReturns.get(methodName);
        if (known != null && !known.getText().equals(value.getText())) {
            ambiguousMethodReturns.add(methodName);
            return;
        }
        localMethodReturns.put(methodName, value);
    }

    /** The {@code return} statement a statement wraps, if it is one. */
    @Nullable private static CSharpParser.ReturnStatementContext findReturnStatement(
            @Nonnull ParseTree statement) {
        if (statement instanceof CSharpParser.ReturnStatementContext returnStatement) {
            return returnStatement;
        }
        for (int i = 0; i < statement.getChildCount(); i++) {
            CSharpParser.ReturnStatementContext found = findReturnStatement(statement.getChild(i));
            if (found != null) {
                return found;
            }
        }
        return null;
    }

    /**
     * The value a local method call returns, if this file declares that method with exactly one
     * return value. Used by {@code CSharpDetectionEngine} to resolve {@code RSA.Create(KeySize())}.
     */
    @Nullable CSharpTree returnValueOf(@Nonnull String methodName) {
        return ambiguousMethodReturns.contains(methodName)
                ? null
                : localMethodReturns.get(methodName);
    }

    /**
     * The bare name of a method, dropping any explicit-interface or namespace qualification ({@code
     * IFoo.Bar} → {@code Bar}), so it matches how the call site spells it.
     */
    @Nullable private static String simpleMethodName(
            @Nullable CSharpParser.Method_member_nameContext memberName) {
        if (memberName == null || memberName.identifier().isEmpty()) {
            return null;
        }
        return memberName.identifier(memberName.identifier().size() - 1).getText();
    }

    /**
     * Gives each formal parameter the value its callers pass, when that value is unambiguous within
     * this file.
     *
     * <p>This is the one piece of inter-procedural resolution the C# engine does. It runs after the
     * whole compilation unit has been converted, because a method's call sites may appear later in
     * the file than the method itself. A parameter is only given a value when <em>every</em>
     * recorded call site of its method supplies an argument for it and all of those arguments are
     * the same expression; a single disagreeing or missing argument leaves the parameter
     * unresolved, matching the G4 guard for locals. Only calls with no receiver or on {@code this}
     * are considered, so a same-named method on another object can never contribute a value.
     *
     * <p>The argument expression keeps the scope of the <em>caller</em> it was converted in, so the
     * engine resolves it against the caller's locals, constants and fields — a caller passing
     * {@code CreateRsa(KeySizeConstant)} resolves just as well as one passing {@code
     * CreateRsa(2048)}.
     */
    private void resolveParametersFromCallSites() {
        for (PendingParameter pending : pendingParameters) {
            List<List<CSharpArgument>> callSites = localCallSites.get(pending.declaringMethod());
            if (callSites == null || callSites.isEmpty()) {
                continue;
            }
            CSharpTree agreed = null;
            for (List<CSharpArgument> arguments : callSites) {
                CSharpTree candidate = argumentFor(arguments, pending.name(), pending.index());
                if (candidate == null) {
                    agreed = null;
                    break;
                }
                if (agreed == null) {
                    agreed = candidate;
                } else if (!agreed.getText().equals(candidate.getText())) {
                    agreed = null;
                    break;
                }
            }
            if (agreed != null) {
                pending.scope()
                        .replace(
                                pending.name(),
                                new CSharpVariable(
                                        pending.name(),
                                        declaredTypeOf(pending),
                                        agreed,
                                        1,
                                        CSharpVariable.Kind.PARAMETER,
                                        agreed.getLine()));
            }
        }
    }

    /**
     * Gives every call to a method of this file the value that method returns, when it has exactly
     * one (see {@link #returnValueOf}). Runs after the whole compilation unit is converted, since
     * the called method may be declared below the call.
     */
    private void resolveLocalCallReturnValues() {
        for (Map.Entry<String, CSharpMethodInvocationTree> entry : localCalls) {
            CSharpTree returnValue = returnValueOf(entry.getKey());
            if (returnValue != null) {
                entry.getValue().setResolvedReturnValue(returnValue);
            }
        }
    }

    @Nullable private static String declaredTypeOf(@Nonnull PendingParameter pending) {
        CSharpVariable existing = pending.scope().lookup(pending.name());
        return existing == null ? null : existing.declaredType();
    }

    /** The argument bound to a parameter: by keyword if present, otherwise by position. */
    @Nullable private static CSharpTree argumentFor(
            @Nonnull List<CSharpArgument> arguments, @Nonnull String parameterName, int index) {
        for (CSharpArgument argument : arguments) {
            if (parameterName.equals(argument.name())) {
                return argument.value();
            }
        }
        if (index < arguments.size() && !arguments.get(index).isNamed()) {
            return arguments.get(index).value();
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // Class-level field scope
    // -------------------------------------------------------------------------

    /**
     * Builds a scope containing the fields declared directly in {@code classBody} (not in nested
     * types) whose value is syntactically certain:
     *
     * <ul>
     *   <li>every {@code const} field — immutable by definition;
     *   <li>every other field that has an initializer <em>and</em> is never assigned anywhere else
     *       in the same class body. A field a constructor or method overwrites has no single value
     *       and is registered with a conflicting-assignment count instead, so the G4 guard in
     *       {@code CSharpDetectionEngine} refuses to resolve it.
     * </ul>
     *
     * <p>Tracking plain fields matters for production code: {@code private static readonly int
     * KeySize = 2048;} at class level is as common as a local, and a {@code const} is only legal
     * for compile-time constants, so any field holding a computed or array value must go through
     * this path.
     */
    @Nonnull
    private CSharpScope buildClassConstScope(
            @Nullable CSharpParser.Class_bodyContext classBody, @Nullable CSharpScope parent) {
        CSharpScope scope = new CSharpScope(parent);
        if (classBody == null || classBody.class_member_declarations() == null) {
            return scope;
        }
        Set<String> reassigned = collectAssignedFieldNames(classBody);
        // A field initializer sits outside every method body, so it is never reached by the
        // statement collector. `private readonly RSA _rsa = RSA.Create(3072);` therefore produced
        // no finding at all. The initializers that are themselves calls are gathered here and
        // handed out as one synthetic block per class, which both makes them analysable and lets a
        // later `_rsa.SignData(...)` attach to the creation, because the creation now carries the
        // field name as its assigned identifier.
        List<CSharpTree> fieldInitializers = new ArrayList<>();
        List<CSharpTree> previousSink = chainCallSink;
        chainCallSink = fieldInitializers;
        try {
            for (CSharpParser.Class_member_declarationContext member :
                    classBody.class_member_declarations().class_member_declaration()) {
                CSharpParser.Common_member_declarationContext common =
                        member.common_member_declaration();
                if (common == null) {
                    continue;
                }
                if (common.constant_declaration() != null) {
                    defineConstantFields(common.constant_declaration(), scope);
                } else if (common.typed_member_declaration() != null
                        && common.typed_member_declaration().field_declaration() != null) {
                    defineInitializedFields(
                            common.typed_member_declaration(),
                            reassigned,
                            scope,
                            fieldInitializers);
                } else if (common.typed_member_declaration() != null
                        && common.typed_member_declaration().property_declaration() != null) {
                    defineInitializedProperty(
                            common.typed_member_declaration(),
                            reassigned,
                            scope,
                            fieldInitializers);
                }
            }
        } finally {
            chainCallSink = previousSink;
        }
        if (!fieldInitializers.isEmpty()) {
            bodies.add(
                    new CSharpBlockTree(
                            classBody.getStart().getLine(),
                            classBody.getStart().getCharPositionInLine(),
                            Collections.unmodifiableList(fieldInitializers),
                            scope));
        }
        return scope;
    }

    /** Registers the declarators of a class-level {@code const Type A = ..., B = ...;}. */
    private void defineConstantFields(
            @Nonnull CSharpParser.Constant_declarationContext constDecl,
            @Nonnull CSharpScope scope) {
        if (constDecl.constant_declarators() == null) {
            return;
        }
        String declaredType = constDecl.type_() != null ? constDecl.type_().getText() : null;
        for (CSharpParser.Constant_declaratorContext declarator :
                constDecl.constant_declarators().constant_declarator()) {
            String name = declarator.identifier().getText();
            CSharpTree initializer =
                    declarator.expression() != null
                            ? convertExpression(declarator.expression(), scope)
                            : null;
            scope.define(
                    name,
                    new CSharpVariable(
                            name,
                            declaredType,
                            initializer,
                            1,
                            CSharpVariable.Kind.CONST,
                            declarator.getStart().getLine()));
        }
    }

    /**
     * Registers the declarators of a class-level field declaration that have an initializer. A
     * field listed in {@code reassigned} is registered with an assignment count of two, which makes
     * the engine's G4 guard treat it as having no single certain value.
     */
    /**
     * The same as {@link #defineInitializedFields} for an auto-property with an initializer, {@code
     * private RSA Key { get; } = RSA.Create(3072);}. The grammar gives this its own declaration
     * shape, but for this engine it behaves exactly like an initialized field: one declared type,
     * one name, one initializing expression.
     */
    private void defineInitializedProperty(
            @Nonnull CSharpParser.Typed_member_declarationContext typedMember,
            @Nonnull Set<String> reassigned,
            @Nonnull CSharpScope scope,
            @Nonnull List<CSharpTree> fieldInitializers) {
        CSharpParser.Property_declarationContext property = typedMember.property_declaration();
        if (property.variable_initializer() == null
                || property.variable_initializer().expression() == null
                || property.member_name() == null) {
            return;
        }
        String name = property.member_name().getText();
        int dot = name.lastIndexOf('.');
        if (dot >= 0) {
            name = name.substring(dot + 1); // an explicit interface implementation
        }
        String declaredType = typedMember.type_() != null ? typedMember.type_().getText() : null;
        CSharpTree initializer =
                convertExpression(property.variable_initializer().expression(), scope, name);
        if (isStatementWorthy(initializer) && !fieldInitializers.contains(initializer)) {
            fieldInitializers.add(initializer);
        }
        scope.define(
                name,
                new CSharpVariable(
                        name,
                        declaredType,
                        initializer,
                        reassigned.contains(name) ? 2 : 1,
                        CSharpVariable.Kind.FIELD,
                        property.getStart().getLine()));
    }

    private void defineInitializedFields(
            @Nonnull CSharpParser.Typed_member_declarationContext typedMember,
            @Nonnull Set<String> reassigned,
            @Nonnull CSharpScope scope,
            @Nonnull List<CSharpTree> fieldInitializers) {
        CSharpParser.Field_declarationContext field = typedMember.field_declaration();
        if (field.variable_declarators() == null) {
            return;
        }
        String declaredType = typedMember.type_() != null ? typedMember.type_().getText() : null;
        for (CSharpParser.Variable_declaratorContext declarator :
                field.variable_declarators().variable_declarator()) {
            CSharpParser.Variable_initializerContext initCtx = declarator.variable_initializer();
            if (initCtx == null || initCtx.expression() == null) {
                continue; // no initializer: no value to resolve
            }
            String name = declarator.identifier().getText();
            // The field name is passed as the assigned identifier so a depending rule written for
            // the creation can later fire on `field.Operation(...)`.
            CSharpTree initializer = convertExpression(initCtx.expression(), scope, name);
            if (isStatementWorthy(initializer) && !fieldInitializers.contains(initializer)) {
                fieldInitializers.add(initializer);
            }
            scope.define(
                    name,
                    new CSharpVariable(
                            name,
                            declaredType,
                            initializer,
                            reassigned.contains(name) ? 2 : 1,
                            CSharpVariable.Kind.FIELD,
                            declarator.getStart().getLine()));
        }
    }

    /**
     * Collects the names assigned to anywhere inside {@code classBody} by a plain assignment
     * ({@code Name = ...} or {@code this.Name = ...}), so a field a constructor or method
     * overwrites is not treated as holding its declared initializer.
     */
    @Nonnull
    private static Set<String> collectAssignedFieldNames(
            @Nonnull CSharpParser.Class_bodyContext classBody) {
        Set<String> assigned = new HashSet<>();
        collectAssignedFieldNames(classBody, assigned);
        return assigned;
    }

    private static void collectAssignedFieldNames(
            @Nonnull ParseTree node, @Nonnull Set<String> assigned) {
        if (node instanceof CSharpParser.AssignmentContext assignment
                && assignment.unary_expression() != null) {
            CSharpParser.Primary_expressionContext lhs =
                    findPrimaryExpression(assignment.unary_expression());
            if (lhs != null) {
                String name = assignedFieldName(lhs);
                if (name != null) {
                    assigned.add(name);
                }
            }
        }
        for (int i = 0; i < node.getChildCount(); i++) {
            collectAssignedFieldNames(node.getChild(i), assigned);
        }
    }

    /**
     * The field name an assignment's left-hand side targets: {@code Name} for a bare identifier,
     * {@code Name} for {@code this.Name}, otherwise {@code null} (a longer path, an indexer, or a
     * property on another object is not a field of this class).
     */
    @Nullable private static String assignedFieldName(@Nonnull CSharpParser.Primary_expressionContext lhs) {
        List<ParseTree> children = lhs.children;
        if (children == null || children.isEmpty()) {
            return null;
        }
        CSharpParser.Primary_expression_startContext start = lhs.primary_expression_start();
        if (children.size() == 1
                && start instanceof CSharpParser.SimpleNameExpressionContext simple) {
            return simple.identifier().getText();
        }
        if (children.size() == 2
                && start != null
                && "this".equals(start.getText())
                && children.get(1) instanceof CSharpParser.Member_accessContext member) {
            return member.identifier().getText();
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // Inner visitor: collects statements within one top-level scope, flattening
    // nested control-flow blocks and discovering lambda/local-function bodies
    // -------------------------------------------------------------------------

    /**
     * Collects method invocations, object creations, and synthetic property-setter invocations from
     * one top-level scope, threading a mutable {@link #currentScope} through nested control-flow
     * blocks (which share this collector's statement list) and local declarations.
     */
    private final class StatementCollector extends CSharpParserBaseVisitor<Void> {

        private final List<CSharpTree> statements = new ArrayList<>();
        @Nonnull private CSharpScope currentScope;

        StatementCollector(@Nonnull CSharpScope scope) {
            this.currentScope = scope;
        }

        @Nonnull
        List<CSharpTree> getStatements() {
            return Collections.unmodifiableList(statements);
        }

        /** The live list, so {@link #convertCallChain} can append a chain's inner calls to it. */
        @Nonnull
        List<CSharpTree> mutableStatements() {
            return statements;
        }

        /**
         * Either flattens a nested control-flow block into this same statement list (in a child
         * scope), or — for anything else (lambda bodies, local-function bodies reached this way,
         * any block shape not on the flatten allow-list) — hands it to {@link #processTopLevelBody}
         * as an independent new top-level scope.
         */
        @Override
        public Void visitBlock(CSharpParser.BlockContext ctx) {
            if (!isFlattenedControlFlowBlock(ctx.getParent())) {
                processTopLevelBody(ctx, new CSharpScope(currentScope));
                return null;
            }
            CSharpScope saved = currentScope;
            currentScope = new CSharpScope(saved);
            if (ctx.statement_list() != null) {
                for (CSharpParser.StatementContext statement : ctx.statement_list().statement()) {
                    visit(statement);
                }
            }
            currentScope = saved;
            return null;
        }

        // ---- declarations ----

        @Override
        public Void visitLocal_variable_declaration(
                CSharpParser.Local_variable_declarationContext ctx) {
            if (ctx.local_variable_type() == null) {
                return null; // `fixed` pointer declarations — not modeled
            }
            String declaredType =
                    ctx.local_variable_type().type_() != null
                            ? ctx.local_variable_type().type_().getText()
                            : null; // null for `var`
            for (CSharpParser.Local_variable_declaratorContext declarator :
                    ctx.local_variable_declarator()) {
                defineLocal(declarator.identifier().getText(), declaredType, declarator);
            }
            return null;
        }

        private void defineLocal(
                @Nonnull String name,
                @Nullable String declaredType,
                @Nonnull CSharpParser.Local_variable_declaratorContext declarator) {
            CSharpParser.Local_variable_initializerContext initCtx =
                    declarator.local_variable_initializer();
            CSharpTree initializerTree = null;
            if (initCtx != null && initCtx.expression() != null) {
                initializerTree = convertExpression(initCtx.expression(), currentScope, name);
                if (isStatementWorthy(initializerTree)) {
                    statements.add(initializerTree);
                }
            }
            currentScope.define(
                    name,
                    new CSharpVariable(
                            name,
                            declaredType,
                            initializerTree,
                            initializerTree != null ? 1 : 0,
                            CSharpVariable.Kind.LOCAL,
                            declarator.getStart().getLine()));
        }

        @Override
        public Void visitLocal_constant_declaration(
                CSharpParser.Local_constant_declarationContext ctx) {
            if (ctx.constant_declarators() == null) {
                return null;
            }
            String declaredType = ctx.type_() != null ? ctx.type_().getText() : null;
            for (CSharpParser.Constant_declaratorContext declarator :
                    ctx.constant_declarators().constant_declarator()) {
                String name = declarator.identifier().getText();
                CSharpTree initializer =
                        declarator.expression() != null
                                ? convertExpression(declarator.expression(), currentScope)
                                : null;
                currentScope.define(
                        name,
                        new CSharpVariable(
                                name,
                                declaredType,
                                initializer,
                                1,
                                CSharpVariable.Kind.CONST,
                                declarator.getStart().getLine()));
            }
            return null;
        }

        @Override
        public Void visitLocal_function_declaration(
                CSharpParser.Local_function_declarationContext ctx) {
            CSharpScope functionScope = new CSharpScope(currentScope);
            if (ctx.local_function_header() != null) {
                defineParameters(
                        ctx.local_function_header().formal_parameter_list(),
                        functionScope,
                        ctx.local_function_header().identifier() != null
                                ? ctx.local_function_header().identifier().getText()
                                : null);
            }
            CSharpParser.Local_function_bodyContext body = ctx.local_function_body();
            if (body != null && body.block() != null) {
                processTopLevelBody(body.block(), functionScope);
            }
            return null;
        }

        // ---- assignment tracking: `x = <expr>;` and `obj.Property = <expr>;` ----

        @Override
        public Void visitAssignment(CSharpParser.AssignmentContext ctx) {
            if (ctx.assignment_operator() == null
                    || ctx.assignment_operator().ASSIGNMENT() == null) {
                return null; // compound operators (+=, etc.) not modeled
            }
            CSharpParser.Primary_expressionContext lhsPrimary =
                    findPrimaryExpression(ctx.unary_expression());
            if (lhsPrimary == null) {
                return null;
            }
            List<ParseTree> children = lhsPrimary.children;
            if (children == null || children.isEmpty()) {
                return null;
            }
            if (!(lhsPrimary.primary_expression_start()
                    instanceof CSharpParser.SimpleNameExpressionContext simpleCtx)) {
                return null;
            }
            CSharpParser.ExpressionContext rhs = ctx.expression();
            if (rhs == null) {
                return null;
            }

            if (children.size() == 1) {
                // Plain reassignment: `x = <expr>;` — re-uses the assignedIdentifier mechanism so
                // `isInitForVariable`/TraceSymbol tracking still recognizes the new value, exactly
                // like a `var x = <expr>;` declaration does.
                String name = simpleCtx.identifier().getText();
                CSharpTree value = convertExpression(rhs, currentScope, name);
                if (isStatementWorthy(value)) {
                    statements.add(value);
                }
                currentScope.recordAssignment(name, value);
                return null;
            }

            // Property-setter form: `obj.Property = value;` — exactly one member_access, no method
            // invocation — synthesized as `set_<Property>(value)`, mirroring CLR accessor
            // semantics.
            String propertyName = null;
            for (int i = 1; i < children.size(); i++) {
                if (children.get(i) instanceof CSharpParser.Member_accessContext memberCtx) {
                    if (propertyName != null) {
                        return null; // chained access like a.b.c — skip
                    }
                    propertyName = memberCtx.identifier().getText();
                } else if (children.get(i) instanceof CSharpParser.Method_invocationContext) {
                    return null; // method call, not a property assignment
                }
            }
            if (propertyName == null) {
                return null;
            }
            String variableName = simpleCtx.identifier().getText();
            String setterName = "set_" + propertyName;
            CSharpTree rhsTree = convertExpression(rhs, currentScope);
            List<CSharpArgument> args =
                    rhsTree != null
                            ? Collections.singletonList(new CSharpArgument(null, rhsTree))
                            : Collections.emptyList();
            statements.add(
                    new CSharpMethodInvocationTree(
                            ctx.getStart().getLine(),
                            ctx.getStart().getCharPositionInLine(),
                            variableName,
                            setterName,
                            args,
                            null,
                            null,
                            currentScope));
            return null;
        }

        // ---- bare expression statements (`Foo();`, `new T();`) ----

        @Override
        public Void visitPrimary_expression(CSharpParser.Primary_expressionContext ctx) {
            CSharpTree node = convertPrimaryExpression(ctx, null, currentScope);
            if (isStatementWorthy(node)) {
                statements.add(node);
            }
            return null;
        }
    }

    /**
     * Whether a nested {@code { }} block should be flattened into its enclosing top-level block's
     * statement list (as opposed to becoming its own independent {@link CSharpBlockTree}). Matches
     * the C# control-flow constructs whose body is a plain nested scope, not a new named scope in
     * its own right: {@code if}/{@code else}, {@code while}/{@code do}/{@code for}/{@code foreach},
     * {@code lock}, {@code fixed}, {@code using} (statement form), a bare nested {@code { }} (all
     * of which wrap their block in {@code if_body} or {@code embedded_statement}), {@code
     * try}/{@code catch}/{@code finally}, and {@code checked}/{@code unchecked}/{@code unsafe}.
     * Everything else (most commonly a lambda body or a local-function body) is treated as a new
     * top-level scope.
     */
    private static boolean isFlattenedControlFlowBlock(@Nullable ParseTree parent) {
        if (parent == null) {
            return false;
        }
        return isFlattenedLoopOrBranchBlock(parent) || isFlattenedExceptionHandlingBlock(parent);
    }

    private static boolean isFlattenedLoopOrBranchBlock(@Nonnull ParseTree parent) {
        return parent instanceof CSharpParser.If_bodyContext
                || parent instanceof CSharpParser.Embedded_statementContext
                || parent instanceof CSharpParser.CheckedStatementContext
                || parent instanceof CSharpParser.UncheckedStatementContext
                || parent instanceof CSharpParser.UnsafeStatementContext;
    }

    private static boolean isFlattenedExceptionHandlingBlock(@Nonnull ParseTree parent) {
        return parent instanceof CSharpParser.TryStatementContext
                || parent instanceof CSharpParser.Specific_catch_clauseContext
                || parent instanceof CSharpParser.General_catch_clauseContext
                || parent instanceof CSharpParser.Finally_clauseContext;
    }

    /** Only invocation/creation/synthetic-setter trees are worth scanning as a "statement". */
    private static boolean isStatementWorthy(@Nullable CSharpTree tree) {
        return tree instanceof CSharpMethodInvocationTree
                || tree instanceof CSharpObjectCreationTree;
    }

    // -------------------------------------------------------------------------
    // Expression conversion (shared by class-const-scope building and StatementCollector)
    // -------------------------------------------------------------------------

    @Nullable private CSharpTree convertExpression(
            @Nullable CSharpParser.ExpressionContext expr, @Nonnull CSharpScope scope) {
        return convertExpression(expr, scope, null);
    }

    /**
     * Converts an expression to its {@link CSharpTree} shape: a literal, an identifier, a member
     * access, an array creation, an invocation/creation, or (for the flat two-operand case) a
     * {@link CSharpBinaryExpressionTree}. {@code assignedIdentifier}, when non-null, is attached to
     * the outermost invocation/creation tree only — it is never propagated into sub-expressions
     * (arguments, operands), matching the "applies to exactly the first/outermost call" rule
     * inherited from the original single-level converter.
     */
    @Nullable private CSharpTree convertExpression(
            @Nullable CSharpParser.ExpressionContext expr,
            @Nonnull CSharpScope scope,
            @Nullable String assignedIdentifier) {
        if (expr == null) {
            return null;
        }
        String text = expr.getText();
        if (text == null || text.isEmpty()) {
            return null;
        }

        ParseTree unwrapped = unwrapSingleChildChain(expr);

        if (unwrapped instanceof CSharpParser.Lambda_expressionContext lambdaCtx) {
            CSharpParser.Anonymous_function_bodyContext body = lambdaCtx.anonymous_function_body();
            if (body != null && body.block() != null) {
                processTopLevelBody(body.block(), new CSharpScope(scope));
            }
            return null; // the lambda itself never contributes a value (see class javadoc)
        }

        if (unwrapped instanceof CSharpParser.Primary_expressionContext primary) {
            CSharpTree converted = convertPrimaryExpression(primary, assignedIdentifier, scope);
            if (converted != null) {
                return converted;
            }
        } else {
            // Any other shape (arithmetic, comparison, logical, ternary, ...) can never itself be
            // call/creation-shaped, so assignedIdentifier does not apply here.
            CSharpTree arithmetic = convertArithmeticOrPrimary(unwrapped, scope);
            if (arithmetic != null) {
                return arithmetic;
            }
        }
        return createLeafFromText(text, expr.getStart(), scope);
    }

    /**
     * Descends through single-child grammar wrapper rules (the many layers between {@code
     * expression} and the actual shape underneath: {@code non_assignment_expression}, {@code
     * conditional_expression}, {@code additive_expression}, ...) down to the first node that either
     * has more than one child (a real binary/ternary/etc. shape) or is itself a {@link
     * CSharpParser.Primary_expressionContext}/{@link CSharpParser.Lambda_expressionContext} —
     * stopping there even if that specific node happens to have only one child itself (a {@code
     * primary_expression} wrapping a single {@code new T(args)} start, with no further
     * member-access chaining, is exactly this case — unwrapping past it would incorrectly reach
     * into its arguments).
     */
    @Nonnull
    private static ParseTree unwrapSingleChildChain(@Nonnull ParseTree node) {
        ParseTree current = node;
        while (current.getChildCount() == 1
                && !(current instanceof CSharpParser.Primary_expressionContext)
                && !(current instanceof CSharpParser.Lambda_expressionContext)) {
            current = current.getChild(0);
        }
        return current;
    }

    /**
     * Recognizes a flat two-operand {@code +}/{@code -}/{@code *}/{@code /}/{@code %} expression
     * (e.g. {@code 256 / 8}); anything more complex (three-or-more-term chains, other operators)
     * falls through to a best-effort search for a single primary expression anywhere inside, same
     * as the pre-refactor fallback behaviour.
     */
    @Nullable private CSharpTree convertArithmeticOrPrimary(
            @Nonnull ParseTree node, @Nonnull CSharpScope scope) {
        ParseTree unwrapped = unwrapSingleChildChain(node);
        if (unwrapped instanceof CSharpParser.Additive_expressionContext add
                && add.multiplicative_expression().size() == 2) {
            String operator = add.PLUS(0) != null ? "+" : "-";
            CSharpTree left = convertArithmeticOrPrimary(add.multiplicative_expression(0), scope);
            CSharpTree right = convertArithmeticOrPrimary(add.multiplicative_expression(1), scope);
            return combineBinary(add, left, operator, right, scope);
        }
        if (unwrapped instanceof CSharpParser.Multiplicative_expressionContext mul
                && mul.unary_expression().size() == 2) {
            String operator = mul.STAR(0) != null ? "*" : mul.DIV(0) != null ? "/" : "%";
            CSharpTree left = convertArithmeticOrPrimary(mul.unary_expression(0), scope);
            CSharpTree right = convertArithmeticOrPrimary(mul.unary_expression(1), scope);
            return combineBinary(mul, left, operator, right, scope);
        }
        if (unwrapped instanceof CSharpParser.Primary_expressionContext primary) {
            return convertPrimaryExpression(primary, null, scope);
        }
        if (unwrapped instanceof CSharpParser.Cast_expressionContext cast) {
            // `(int)x` — the cast does not change which value is meant.
            return convertArithmeticOrPrimary(cast.unary_expression(), scope);
        }
        if (unwrapped instanceof CSharpParser.Unary_expressionContext unary) {
            return convertUnaryExpression(unary, scope);
        }
        // Any other shape — a ternary, a `??`, a switch expression, a comparison, a lambda, a LINQ
        // query — has no single syntactically certain value. Earlier versions fell back to "find
        // the first primary_expression anywhere inside", which silently picked an unrelated
        // sub-expression: the *condition* of `strong ? 4096 : 2048`, or the *subject* of a switch
        // expression. Combined with a size factory that turned out to be a real false-positive
        // source (a resolvable condition variable became a key length), so these shapes now
        // deliberately resolve to nothing.
        return null;
    }

    /**
     * Converts a unary expression by looking through the operators that do not change which value
     * is meant ({@code +x}, {@code await x}, {@code &x}, {@code *x}) and folding a negation ({@code
     * -x}). Operators that do change the value in ways this converter does not model ({@code ++},
     * {@code --}, {@code !}, {@code ~}, {@code ^}) resolve to nothing.
     */
    @Nullable private CSharpTree convertUnaryExpression(
            @Nonnull CSharpParser.Unary_expressionContext unary, @Nonnull CSharpScope scope) {
        if (unary.cast_expression() != null) {
            return convertArithmeticOrPrimary(unary.cast_expression().unary_expression(), scope);
        }
        if (unary.primary_expression() != null) {
            return convertPrimaryExpression(unary.primary_expression(), null, scope);
        }
        CSharpParser.Unary_expressionContext operand = unary.unary_expression();
        if (operand == null) {
            return null;
        }
        String operator = unary.getChild(0).getText();
        return switch (operator) {
            case "+", "await", "&", "*" -> convertArithmeticOrPrimary(operand, scope);
            case "-" -> negate(unary, convertArithmeticOrPrimary(operand, scope), scope);
            default -> null;
        };
    }

    /** Models {@code -x} as {@code 0 - x} so the engine's arithmetic folding handles it. */
    @Nullable private CSharpTree negate(
            @Nonnull CSharpParser.Unary_expressionContext source,
            @Nullable CSharpTree operand,
            @Nonnull CSharpScope scope) {
        if (operand == null) {
            return null;
        }
        int line = source.getStart().getLine();
        int column = source.getStart().getCharPositionInLine();
        return new CSharpBinaryExpressionTree(
                line,
                column,
                new CSharpLiteralTree(line, column, CSharpLiteralTree.Kind.INTEGER, "0"),
                "-",
                operand,
                scope);
    }

    @Nullable private CSharpTree combineBinary(
            @Nonnull ParseTree source,
            @Nullable CSharpTree left,
            @Nonnull String operator,
            @Nullable CSharpTree right,
            @Nonnull CSharpScope scope) {
        if (left == null
                || right == null
                || !(source instanceof org.antlr.v4.runtime.ParserRuleContext ctx)) {
            return null;
        }
        return new CSharpBinaryExpressionTree(
                ctx.getStart().getLine(),
                ctx.getStart().getCharPositionInLine(),
                left,
                operator,
                right,
                scope);
    }

    // -----------------------------------------------------------------------
    // Primary expression conversion
    // -----------------------------------------------------------------------

    /**
     * Converts a primary_expression that is call/creation-shaped, or delegates to {@link
     * #convertPrimaryExpressionStart} for the leaf cases (literal, identifier, member-access
     * chain).
     */
    @Nullable private CSharpTree convertPrimaryExpression(
            @Nonnull CSharpParser.Primary_expressionContext ctx,
            @Nullable String assignedIdentifier,
            @Nonnull CSharpScope scope) {
        CSharpParser.Primary_expression_startContext start = ctx.primary_expression_start();

        // Pattern: new AesManaged(), new AesGcm(key), new byte[32], etc.
        if (start instanceof CSharpParser.StackallocExpressionContext stackallocCtx) {
            return convertStackalloc(stackallocCtx, scope);
        }
        if (start instanceof CSharpParser.ObjectCreationExpressionContext objCreationCtx) {
            return convertObjectCreationFromStart(objCreationCtx, assignedIdentifier, scope);
        }

        List<ParseTree> children = ctx.children;
        if (children == null || children.size() < 2) {
            return convertPrimaryExpressionStart(ctx, scope);
        }

        boolean hasInvocation =
                children.stream()
                        .anyMatch(child -> child instanceof CSharpParser.Method_invocationContext);
        if (!hasInvocation) {
            // Pure member-access chain, no call — e.g. ECCurve.NamedCurves.nistP256 as an argument
            return convertPrimaryExpressionStart(ctx, scope);
        }
        return convertCallChain(ctx, children, assignedIdentifier, scope);
    }

    /**
     * Converts a (possibly chained) call expression into invocation trees.
     *
     * <p>A {@code primary_expression} can hold a whole chain of calls and member accesses in one
     * flat child list, e.g. {@code SHA256.Create().ComputeHash(data)} → {@code [SHA256, .Create,
     * (), .ComputeHash, (data)]}. This method walks that list left to right and produces one {@link
     * CSharpMethodInvocationTree} per call. Only the <em>last</em> call is returned (it is the
     * expression's value, and the one an {@code assignedIdentifier} belongs to); every earlier call
     * in the chain is emitted as its own statement via {@link #chainCallSink}, so that e.g. the
     * {@code SHA256.Create()} half of the example is detected in its own right instead of being
     * swallowed by the outer call.
     *
     * <p>The receiver of a chained call is the chain's <em>root</em> type name, not the preceding
     * method name: in {@code SHA256.Create().ComputeHash(data)} the object {@code ComputeHash} is
     * called on is a {@code SHA256} (the .NET factory convention {@code X.Create() -> X}), so the
     * receiver reported is {@code "SHA256"}. Reporting the previous member name (the pre-rewrite
     * behaviour, which yielded {@code "Create"}) made every such chain unmatchable by a rule
     * declaring {@code forObjectTypes("SHA256")}.
     *
     * <p>A bare call with no receiver at all ({@code Helper()}, a local or inherited method) gets
     * an empty receiver name: it still becomes a real invocation tree — so a rule declared with
     * {@code forObjectTypes(MethodMatcher.ANY)} can match it and depending rules can fire on its
     * arguments — but it can never satisfy a rule that names a concrete type.
     */
    @Nullable private CSharpTree convertCallChain(
            @Nonnull CSharpParser.Primary_expressionContext ctx,
            @Nonnull List<ParseTree> children,
            @Nullable String assignedIdentifier,
            @Nonnull CSharpScope scope) {
        int line = ctx.getStart().getLine();
        int column = ctx.getStart().getCharPositionInLine();
        CSharpParser.Primary_expression_startContext start = ctx.primary_expression_start();

        // The receiver the next call in the chain is made on.
        String receiver = "";
        // A creation at the head of the chain (`new AesManaged().CreateEncryptor()`) is itself a
        // detectable expression and is emitted separately, with the created type as the receiver.
        CSharpTree headCreation = null;
        if (start instanceof CSharpParser.SimpleNameExpressionContext simpleCtx) {
            receiver = simpleCtx.identifier().getText();
        } else if (start instanceof CSharpParser.ObjectCreationExpressionContext creationCtx) {
            headCreation = convertObjectCreationFromStart(creationCtx, null, scope);
            if (headCreation instanceof CSharpObjectCreationTree created) {
                receiver = created.getTypeName();
            }
        }

        // Pending member name, i.e. the `.Foo` that a following `(...)` turns into a call.
        String pendingMember = null;
        // Calls in source order, collected before any tree is built so that only the final one —
        // the chain's value — is given the assignedIdentifier.
        List<PendingCall> pending = new ArrayList<>();
        for (int i = 1; i < children.size(); i++) {
            ParseTree child = children.get(i);
            if (child instanceof CSharpParser.Member_accessContext memberAccess) {
                if (pendingMember != null) {
                    // `A.B.C(...)`: B is part of the receiver path, not a call.
                    receiver = pendingMember;
                }
                pendingMember = memberAccess.identifier().getText();
            } else if (child instanceof CSharpParser.Method_invocationContext methodInv) {
                String methodName = pendingMember;
                pendingMember = null;
                List<CSharpArgument> args = convertArgumentList(methodInv.argument_list(), scope);
                if (methodName == null) {
                    // A bare `Foo(...)` — the name sits in the expression start, not in a
                    // member_access, and there is no receiver.
                    methodName = receiver;
                    receiver = "";
                }
                pending.add(new PendingCall(receiver, methodName, args));
            }
            // bracket_expression / '!' / '++' / '--' / '->' are irrelevant to the call shape.
        }

        if (pending.isEmpty()) {
            return headCreation;
        }
        if (headCreation != null) {
            emitChainCall(headCreation);
        }
        // Everything but the final call is a statement of its own; the final call is the value.
        CSharpMethodInvocationTree value = null;
        for (int i = 0; i < pending.size(); i++) {
            PendingCall call = pending.get(i);
            boolean isLast = i == pending.size() - 1;
            CSharpMethodInvocationTree tree =
                    new CSharpMethodInvocationTree(
                            line,
                            column,
                            call.receiver(),
                            call.methodName(),
                            call.arguments(),
                            isLast ? assignedIdentifier : null,
                            null,
                            scope);
            if (call.receiver().isEmpty() || "this".equals(call.receiver())) {
                // A call that can only target a method of the enclosing type — usable both for
                // resolving that method's parameters (see resolveParametersFromCallSites) and for
                // resolving this call's own value from that method's return expression.
                localCallSites
                        .computeIfAbsent(call.methodName(), key -> new ArrayList<>())
                        .add(call.arguments());
                localCalls.add(Map.entry(call.methodName(), tree));
            }
            if (isLast) {
                value = tree;
            } else {
                emitChainCall(tree);
            }
        }
        return value;
    }

    /** One call of a chain, before the tree is built (see {@link #convertCallChain}). */
    private record PendingCall(
            @Nonnull String receiver,
            @Nonnull String methodName,
            @Nonnull List<CSharpArgument> arguments) {}

    /** Adds an inner call of a chain to the statement list currently being collected, if any. */
    private void emitChainCall(@Nonnull CSharpTree call) {
        if (chainCallSink != null) {
            chainCallSink.add(call);
        }
    }

    /**
     * Converts a primary_expression to its leaf form: literal, identifier, or member-access chain.
     *
     * <p>An element access ({@code sizes[0]}, {@code dict["k"]}) resolves to nothing: the value is
     * one <em>element</em>, and this converter cannot evaluate the index. Modelling it as the
     * indexed variable itself would be actively wrong — {@code RSA.Create(sizes[0])} would then
     * resolve {@code sizes} to its array initializer and report the array's <em>length</em> as the
     * key size.
     */
    @Nullable private CSharpTree convertPrimaryExpressionStart(
            @Nonnull CSharpParser.Primary_expressionContext ctx, @Nonnull CSharpScope scope) {
        CSharpParser.Primary_expression_startContext start = ctx.primary_expression_start();

        if (ctx.children != null
                && ctx.children.stream()
                        .anyMatch(
                                child -> child instanceof CSharpParser.Bracket_expressionContext)) {
            return null;
        }

        if (start instanceof CSharpParser.LiteralExpressionContext literalCtx) {
            return convertLiteral(literalCtx.literal());
        }

        if (start instanceof CSharpParser.StackallocExpressionContext stackallocCtx) {
            return convertStackalloc(stackallocCtx, scope);
        }
        if (start instanceof CSharpParser.ObjectCreationExpressionContext objCreationCtx) {
            return convertObjectCreationFromStart(objCreationCtx, null, scope);
        }

        if (start instanceof CSharpParser.ParenthesisExpressionsContext parens) {
            // `(2048)` — parentheses do not change which value is meant.
            return convertExpression(parens.expression(), scope);
        }

        if (start instanceof CSharpParser.SimpleNameExpressionContext simpleCtx) {
            String name = simpleCtx.identifier().getText();
            List<ParseTree> children = ctx.children;
            if (children != null && children.size() >= 2) {
                // Collect the FULL run of consecutive member accesses (handles arbitrarily deep
                // chains like ECCurve.NamedCurves.nistP256, not just the first segment).
                List<String> chain = new ArrayList<>();
                chain.add(name);
                for (int i = 1; i < children.size(); i++) {
                    if (children.get(i) instanceof CSharpParser.Member_accessContext memberCtx) {
                        chain.add(memberCtx.identifier().getText());
                    } else {
                        break;
                    }
                }
                if (chain.size() > 1) {
                    String member = chain.get(chain.size() - 1);
                    String qualifier = String.join(".", chain.subList(0, chain.size() - 1));
                    String root = chain.get(0);
                    return new CSharpMemberAccessTree(
                            ctx.getStart().getLine(),
                            ctx.getStart().getCharPositionInLine(),
                            root,
                            qualifier,
                            member);
                }
            }
            return new CSharpIdentifierTree(
                    ctx.getStart().getLine(), ctx.getStart().getCharPositionInLine(), name, scope);
        }

        return null;
    }

    /** Handles the {@code new Type(...)} and {@code new Type[...]} patterns. */
    @Nullable private CSharpTree convertObjectCreationFromStart(
            @Nonnull CSharpParser.ObjectCreationExpressionContext objCreationCtx,
            @Nullable String assignedIdentifier,
            @Nonnull CSharpScope scope) {
        CSharpParser.Type_Context typeCtx = objCreationCtx.type_();

        boolean isArrayForm =
                (objCreationCtx.expression_list() != null
                                && !objCreationCtx.expression_list().expression().isEmpty())
                        || !objCreationCtx.rank_specifier().isEmpty();
        if (isArrayForm) {
            return convertArrayCreation(objCreationCtx, typeCtx, scope);
        }

        if (typeCtx == null) {
            return null; // anonymous object `new { ... }` — not modeled
        }
        String typeName = typeCtx.getText();
        int ltIdx = typeName.indexOf('<');
        if (ltIdx > 0) {
            typeName = typeName.substring(0, ltIdx);
        }

        List<CSharpArgument> args = Collections.emptyList();
        CSharpParser.Object_creation_expressionContext objExpr =
                objCreationCtx.object_creation_expression();
        if (objExpr != null) {
            args = convertArgumentList(objExpr.argument_list(), scope);
        }

        CSharpObjectCreationTree creation =
                new CSharpObjectCreationTree(
                        objCreationCtx.getStart().getLine(),
                        objCreationCtx.getStart().getCharPositionInLine(),
                        typeName,
                        args,
                        assignedIdentifier,
                        null,
                        scope);

        // `new AesManaged { Mode = CipherMode.CBC, KeySize = 256 }` — an object initializer sets
        // the same properties as `aes.Mode = ...;` would, so it is emitted as the same synthetic
        // `set_<Property>` invocations. Every existing property-setter rule therefore covers the
        // initializer form too, with no rule change at all.
        CSharpParser.Object_or_collection_initializerContext initializer =
                objCreationCtx.object_or_collection_initializer() != null
                        ? objCreationCtx.object_or_collection_initializer()
                        : (objExpr != null ? objExpr.object_or_collection_initializer() : null);
        if (initializer != null) {
            emitObjectInitializerSetters(assignedIdentifier, initializer, scope);
        }

        return creation;
    }

    /**
     * Emits one synthetic {@code set_<Property>} invocation per {@code Property = value} entry of
     * an object initializer, on the variable the created object is assigned to.
     *
     * <p>Only simple {@code Property = value} entries are emitted. A nested initializer ({@code
     * Inner = { ... }}) or an indexed entry ({@code [key] = value}) carries no property name that a
     * rule could match, and a collection initializer has no property names at all, so both are
     * skipped. Nothing is emitted when the creation is not assigned to a variable (e.g. it is
     * passed straight into another call), since there would be no receiver name to attach the
     * setters to.
     */
    private void emitObjectInitializerSetters(
            @Nullable String receiver,
            @Nonnull CSharpParser.Object_or_collection_initializerContext initializer,
            @Nonnull CSharpScope scope) {
        CSharpParser.Collection_initializerContext collection =
                initializer.collection_initializer();
        if (collection != null) {
            // `new List<Holder> { new Holder { ... }, ... }` — a collection initializer has no
            // property names, so there is nothing to emit a setter for, but its elements can hold
            // cryptography and have to be walked. This is how test data builders and registration
            // tables are written.
            for (CSharpParser.Element_initializerContext element :
                    collection.element_initializer()) {
                if (element.non_assignment_expression() != null) {
                    emitIfStatementWorthy(
                            convertArithmeticOrPrimary(element.non_assignment_expression(), scope));
                }
                if (element.expression_list() != null) {
                    for (CSharpParser.ExpressionContext expr :
                            element.expression_list().expression()) {
                        emitIfStatementWorthy(convertExpression(expr, scope));
                    }
                }
            }
            return;
        }

        CSharpParser.Object_initializerContext objectInitializer = initializer.object_initializer();
        if (objectInitializer == null || objectInitializer.member_initializer_list() == null) {
            return;
        }
        for (CSharpParser.Member_initializerContext member :
                objectInitializer.member_initializer_list().member_initializer()) {
            if (member.initializer_value() == null) {
                continue;
            }
            CSharpParser.Initializer_valueContext initValue = member.initializer_value();
            if (initValue.object_or_collection_initializer() != null) {
                // `Inner = { ... }` — recurse so nested cryptography is still reached. There is no
                // receiver name for the inner object, so only its values are walked.
                emitObjectInitializerSetters(
                        null, initValue.object_or_collection_initializer(), scope);
                continue;
            }
            CSharpParser.ExpressionContext valueExpr = initValue.expression();
            if (valueExpr == null) {
                continue;
            }
            CSharpTree value = convertExpression(valueExpr, scope);
            if (value == null) {
                continue;
            }
            // The value is a call site in its own right whenever it creates or invokes something,
            // which is what makes `SecurityKey = new RsaSecurityKey(RSA.Create(2048))` visible.
            // This happens regardless of whether a setter can be emitted below.
            emitIfStatementWorthy(value);

            if (receiver == null || member.identifier() == null) {
                // Without a receiver name there is nothing a property-setter rule could match on,
                // and an indexed entry (`[key] = value`) carries no property name either.
                continue;
            }
            emitChainCall(
                    new CSharpMethodInvocationTree(
                            member.getStart().getLine(),
                            member.getStart().getCharPositionInLine(),
                            receiver,
                            "set_" + member.identifier().getText(),
                            Collections.singletonList(new CSharpArgument(null, value)),
                            null,
                            null,
                            scope));
        }
    }

    /** Emits {@code tree} as a statement of its own when it creates or invokes something. */
    private void emitIfStatementWorthy(@Nullable CSharpTree tree) {
        if (isStatementWorthy(tree) && chainCallSink != null && !chainCallSink.contains(tree)) {
            chainCallSink.add(tree);
        }
    }

    /**
     * Handles {@code stackalloc byte[32]} and {@code stackalloc byte[] { ... }}.
     *
     * <p>Modelled as an array creation, because for this engine's purposes it is one: the length is
     * what a size factory reads, and whether the buffer lives on the stack or the heap makes no
     * difference to it. This matters more than the syntax's rarity suggests, since the {@code
     * Span<byte>} overloads of the AEAD and key derivation APIs exist precisely so callers can use
     * {@code stackalloc}, so in modern .NET crypto code the nonce, tag and salt lengths are often
     * stated this way and no other.
     */
    @Nullable private CSharpTree convertStackalloc(
            @Nonnull CSharpParser.StackallocExpressionContext ctx, @Nonnull CSharpScope scope) {
        CSharpParser.Stackalloc_initializerContext init = ctx.stackalloc_initializer();
        if (init == null) {
            return null;
        }
        String elementType = init.type_() != null ? init.type_().getText() : null;
        int line = ctx.getStart().getLine();
        int col = ctx.getStart().getCharPositionInLine();

        if (init.OPEN_BRACE() != null) {
            // stackalloc T[] { a, b, c } — the element count is the length
            int count = init.expression().size();
            return new CSharpArrayCreationTree(line, col, elementType, null, count, scope);
        }
        if (!init.expression().isEmpty()) {
            CSharpTree length = convertExpression(init.expression(0), scope);
            return new CSharpArrayCreationTree(line, col, elementType, length, -1, scope);
        }
        return new CSharpArrayCreationTree(line, col, elementType, null, -1, scope);
    }

    @Nonnull
    private CSharpTree convertArrayCreation(
            @Nonnull CSharpParser.ObjectCreationExpressionContext ctx,
            @Nullable CSharpParser.Type_Context typeCtx,
            @Nonnull CSharpScope scope) {
        String elementType = typeCtx != null ? typeCtx.getText() : null;
        int line = ctx.getStart().getLine();
        int col = ctx.getStart().getCharPositionInLine();

        if (ctx.expression_list() != null && !ctx.expression_list().expression().isEmpty()) {
            // new T[expr, ...] — explicit size; only the first dimension is tracked
            CSharpTree length = convertExpression(ctx.expression_list().expression(0), scope);
            return new CSharpArrayCreationTree(line, col, elementType, length, -1, scope);
        }
        if (ctx.array_initializer() != null) {
            int count = ctx.array_initializer().variable_initializer().size();
            return new CSharpArrayCreationTree(line, col, elementType, null, count, scope);
        }
        return new CSharpArrayCreationTree(line, col, elementType, null, -1, scope);
    }

    // -----------------------------------------------------------------------
    // Argument conversion
    // -----------------------------------------------------------------------

    @Nonnull
    private List<CSharpArgument> convertArgumentList(
            @Nullable CSharpParser.Argument_listContext argListCtx, @Nonnull CSharpScope scope) {
        if (argListCtx == null) {
            return Collections.emptyList();
        }
        List<CSharpArgument> args = new ArrayList<>();
        for (CSharpParser.ArgumentContext arg : argListCtx.argument()) {
            CSharpArgument argument = convertArgument(arg, scope);
            if (argument != null) {
                args.add(argument);
            }
        }
        return Collections.unmodifiableList(args);
    }

    /**
     * Converts one call argument, keeping its keyword name when written as {@code name: value} so
     * that {@link CSharpNamedArgumentBinder} can bind it to the parameter a rule declared via
     * {@code withNamedParameter}. {@code ref}/{@code out}/{@code in} modifiers are ignored — they
     * do not change which parameter an argument belongs to.
     */
    @Nullable private CSharpArgument convertArgument(
            @Nonnull CSharpParser.ArgumentContext arg, @Nonnull CSharpScope scope) {
        CSharpParser.ExpressionContext expr = arg.expression();
        if (expr == null) {
            return null;
        }
        CSharpTree value = convertExpression(expr, scope);
        if (value == null) {
            // Keep the argument's position even though its value is unknown — see
            // CSharpUnknownTree for why dropping it would break arity-based rule matching.
            value =
                    new CSharpUnknownTree(
                            expr.getStart().getLine(),
                            expr.getStart().getCharPositionInLine(),
                            expr.getText());
        }
        // A crypto creation written as an argument of another call is a call site in its own
        // right: `new Wrapper(RSA.Create(2048))` and `Register(RSA.Create(2048))` are how wrapper
        // types, dependency injection and fluent builders are written, and without this the whole
        // finding is lost, not just its parameters. Emitting it into the same sink that
        // convertCallChain uses for a chain's inner calls makes it an analysable statement while
        // it also stays the argument's value, so a rule that reads the argument is unaffected.
        if (isStatementWorthy(value) && chainCallSink != null) {
            chainCallSink.add(value);
        }
        String name =
                arg.identifier() != null && arg.COLON() != null ? arg.identifier().getText() : null;
        return new CSharpArgument(name, value);
    }

    /**
     * Walks an expression to find the first primary_expression child (handles intermediate grammar
     * rules before reaching primary).
     */
    @Nullable private static CSharpParser.Primary_expressionContext findPrimaryExpression(
            @Nonnull ParseTree tree) {
        if (tree instanceof CSharpParser.Primary_expressionContext primary) {
            return primary;
        }
        for (int i = 0; i < tree.getChildCount(); i++) {
            CSharpParser.Primary_expressionContext found = findPrimaryExpression(tree.getChild(i));
            if (found != null) {
                return found;
            }
        }
        return null;
    }

    @Nullable private CSharpTree convertLiteral(@Nullable CSharpParser.LiteralContext literalCtx) {
        if (literalCtx == null) {
            return null;
        }
        String text = literalCtx.getText();
        int line = literalCtx.getStart().getLine();
        int col = literalCtx.getStart().getCharPositionInLine();

        if (literalCtx.INTEGER_LITERAL() != null) {
            return new CSharpLiteralTree(line, col, CSharpLiteralTree.Kind.INTEGER, text);
        }
        if (literalCtx.REAL_LITERAL() != null) {
            return new CSharpLiteralTree(line, col, CSharpLiteralTree.Kind.REAL, text);
        }
        if (literalCtx.string_literal() != null) {
            String value = text;
            if (value.length() >= 2 && value.charAt(0) == '"') {
                value = value.substring(1, value.length() - 1);
            } else if (value.startsWith("@\"") && value.endsWith("\"")) {
                value = value.substring(2, value.length() - 1);
            }
            return new CSharpLiteralTree(line, col, CSharpLiteralTree.Kind.STRING, value);
        }
        if (literalCtx.CHARACTER_LITERAL() != null) {
            return new CSharpLiteralTree(line, col, CSharpLiteralTree.Kind.CHARACTER, text);
        }
        if (literalCtx.boolean_literal() != null) {
            return new CSharpLiteralTree(line, col, CSharpLiteralTree.Kind.BOOLEAN, text);
        }
        if (literalCtx.NULL_() != null) {
            return new CSharpLiteralTree(line, col, CSharpLiteralTree.Kind.NULL, "null");
        }
        return new CSharpLiteralTree(line, col, CSharpLiteralTree.Kind.STRING, text);
    }

    /**
     * Last-resort fallback: creates a leaf node by inspecting the raw text of an expression whose
     * shape was not recognized.
     *
     * <p>Only shapes whose text is unambiguously a literal, a plain identifier, or a dotted name
     * are accepted. Anything else resolves to nothing rather than being turned into an identifier
     * named after the raw source text: ANTLR's {@code getText()} concatenates a whole expression
     * without whitespace, so a ternary used as an argument would otherwise become an "identifier"
     * literally named {@code strong?4096:2048}, and an element access one named {@code sizes[0]} —
     * names that can never resolve, but that do reach the value factories as strings.
     */
    @Nullable private CSharpTree createLeafFromText(
            @Nonnull String text, @Nullable Token startToken, @Nonnull CSharpScope scope) {
        int line = startToken != null ? startToken.getLine() : 0;
        int col = startToken != null ? startToken.getCharPositionInLine() : 0;

        if (text.isEmpty() || "null".equals(text)) {
            return null;
        }
        try {
            Integer.parseInt(text);
            return new CSharpLiteralTree(line, col, CSharpLiteralTree.Kind.INTEGER, text);
        } catch (NumberFormatException ignored) {
            // not integer
        }
        if ((text.startsWith("\"") && text.endsWith("\""))
                || (text.startsWith("@\"") && text.endsWith("\""))) {
            String value = text.replaceAll("^@?\"|\"$", "");
            return new CSharpLiteralTree(line, col, CSharpLiteralTree.Kind.STRING, value);
        }
        int dotIdx = text.lastIndexOf('.');
        if (dotIdx > 0) {
            String typePart = text.substring(0, dotIdx);
            String memberPart = text.substring(dotIdx + 1);
            if (isDottedName(typePart) && isSimpleIdentifier(memberPart)) {
                return new CSharpMemberAccessTree(line, col, typePart, memberPart);
            }
            return null;
        }
        return isSimpleIdentifier(text) ? new CSharpIdentifierTree(line, col, text, scope) : null;
    }

    /** Whether {@code text} is a single C# identifier (so it could name a variable we track). */
    private static boolean isSimpleIdentifier(@Nonnull String text) {
        if (text.isEmpty() || Character.isDigit(text.charAt(0))) {
            return false;
        }
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (!Character.isLetterOrDigit(c) && c != '_' && c != '@') {
                return false;
            }
        }
        return true;
    }

    /** Whether {@code text} is a dotted chain of identifiers, e.g. {@code ECCurve.NamedCurves}. */
    private static boolean isDottedName(@Nonnull String text) {
        if (text.isEmpty()) {
            return false;
        }
        for (String segment : text.split("\\.", -1)) {
            if (!isSimpleIdentifier(segment)) {
                return false;
            }
        }
        return true;
    }
}
