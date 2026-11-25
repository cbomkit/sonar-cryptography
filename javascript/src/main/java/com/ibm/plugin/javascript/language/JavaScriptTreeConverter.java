/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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
package com.ibm.plugin.javascript.language;

import com.ibm.plugin.javascript.antlr.TypeScriptParser;
import com.ibm.plugin.javascript.tree.JavaScriptBlockTree;
import com.ibm.plugin.javascript.tree.JavaScriptCallTree;
import com.ibm.plugin.javascript.tree.JavaScriptIdentifierTree;
import com.ibm.plugin.javascript.tree.JavaScriptLiteralTree;
import com.ibm.plugin.javascript.tree.JavaScriptMemberTree;
import com.ibm.plugin.javascript.tree.JavaScriptScope;
import com.ibm.plugin.javascript.tree.JavaScriptTree;
import com.ibm.plugin.javascript.tree.JavaScriptUnknownTree;
import com.ibm.plugin.javascript.tree.JavaScriptVariable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.antlr.v4.runtime.ParserRuleContext;
import org.antlr.v4.runtime.Token;
import org.antlr.v4.runtime.tree.ParseTree;

/**
 * Converts the ANTLR4 TypeScript/JavaScript parse tree into the {@link JavaScriptTree} model the
 * detection engine consumes.
 *
 * <p>The converter produces one {@link JavaScriptBlockTree} for the module body and one for every
 * function, method and arrow-function body. Inside a block it records every call in source order
 * and builds a {@link JavaScriptScope} symbol table of the {@code const}/{@code let}/{@code var}
 * bindings, so that identifiers passed as arguments can be resolved to the literal they were
 * initialised with.
 *
 * <p><b>Call chains are desugared.</b> The engine's dependent-rule traversal looks for later calls
 * <em>on a tracked variable</em>. A chained call such as {@code
 * crypto.createHash('sha512').update(x).digest('hex')} has no variable, so each intermediate result
 * is given a synthetic name ({@code $chain0}): the converter emits {@code createHash} assigned to
 * {@code $chain0}, then {@code update} and {@code digest} with receiver {@code $chain0}. The
 * sequential form ({@code const h = crypto.createHash(..); h.update(x)}) and the chained form then
 * reach the engine as the same shape.
 *
 * <p><b>Module aliases.</b> {@code import * as c from 'node:crypto'}, {@code import crypto from
 * 'crypto'} and {@code const c = require('crypto')} register {@code c} as an alias, and calls are
 * emitted with the canonical module name ({@code crypto}) as receiver. {@code import { createHash }
 * from 'crypto'} registers a bound member, so a bare {@code createHash(..)} is emitted as {@code
 * crypto.createHash(..)}.
 *
 * <p><b>Known gaps</b> (deliberate for the feasibility spike):
 *
 * <ul>
 *   <li>Function parameters are not entered into the scope, so a parameter that shadows an outer
 *       constant would wrongly resolve to the constant.
 *   <li>Destructuring requires ({@code const { createHash } = require('crypto')}) are not bound.
 *   <li>Nothing resolves across files, and no inter-procedural value flow is modelled.
 *   <li>Template literals with substitutions, object literals and spreads become {@link
 *       JavaScriptUnknownTree}.
 * </ul>
 */
public final class JavaScriptTreeConverter {

    private record BoundMember(@Nonnull String module, @Nonnull String member) {}

    @Nonnull private final Map<String, String> moduleAliases = new HashMap<>();
    @Nonnull private final Map<String, BoundMember> boundMembers = new HashMap<>();
    private int chainCounter = 0;

    /** Extracts the module block and one block per function body of the compilation unit. */
    @Nonnull
    public List<JavaScriptBlockTree> extractBlocks(@Nonnull TypeScriptParser.ProgramContext root) {
        collectBindings(root);
        List<JavaScriptBlockTree> blocks = new ArrayList<>();
        JavaScriptScope moduleScope = new JavaScriptScope(null);
        List<JavaScriptTree> moduleStatements = new ArrayList<>();
        walk(root, moduleScope, moduleStatements, blocks);
        if (!moduleStatements.isEmpty()) {
            blocks.add(new JavaScriptBlockTree(1, 0, moduleStatements, moduleScope));
        }
        return blocks;
    }

    // -------------------------------------------------------------------------
    // Module bindings (imports / require)
    // -------------------------------------------------------------------------

    private void collectBindings(@Nonnull ParseTree node) {
        if (node instanceof TypeScriptParser.ImportFromBlockContext importBlock) {
            registerImport(importBlock);
        } else if (node instanceof TypeScriptParser.VariableDeclarationContext declaration) {
            registerRequire(declaration);
        }
        for (int i = 0; i < node.getChildCount(); i++) {
            collectBindings(node.getChild(i));
        }
    }

    private void registerImport(@Nonnull TypeScriptParser.ImportFromBlockContext block) {
        if (block.importFrom() == null) {
            return;
        }
        String module = canonicalModule(unquote(block.importFrom().StringLiteral().getText()));
        if (block.importDefault() != null) {
            List<TypeScriptParser.IdentifierNameContext> names =
                    block.importDefault().aliasName().identifierName();
            moduleAliases.put(names.get(names.size() - 1).getText(), module);
        }
        if (block.importNamespace() != null) {
            List<TypeScriptParser.IdentifierNameContext> names =
                    block.importNamespace().identifierName();
            if (!names.isEmpty()) {
                moduleAliases.put(names.get(names.size() - 1).getText(), module);
            }
        }
        if (block.importModuleItems() != null) {
            for (TypeScriptParser.ImportAliasNameContext item :
                    block.importModuleItems().importAliasName()) {
                String member = item.moduleExportName().getText();
                String local =
                        item.importedBinding() != null ? item.importedBinding().getText() : member;
                boundMembers.put(local, new BoundMember(module, member));
            }
        }
    }

    private void registerRequire(@Nonnull TypeScriptParser.VariableDeclarationContext declaration) {
        if (declaration.identifierOrKeyWord() == null) {
            return;
        }
        TypeScriptParser.SingleExpressionContext init = initializerOf(declaration);
        if (init instanceof TypeScriptParser.ArgumentsExpressionContext call
                && call.singleExpression()
                        instanceof TypeScriptParser.IdentifierExpressionContext id
                && "require".equals(id.identifierName().getText())
                && call.arguments().argumentList() != null
                && call.arguments().argumentList().argument().size() == 1) {
            TypeScriptParser.SingleExpressionContext arg =
                    call.arguments().argumentList().argument(0).singleExpression();
            if (arg instanceof TypeScriptParser.LiteralExpressionContext literal
                    && literal.literal().StringLiteral() != null) {
                moduleAliases.put(
                        declaration.identifierOrKeyWord().getText(),
                        canonicalModule(unquote(literal.literal().StringLiteral().getText())));
            }
        }
    }

    @Nonnull
    private static String canonicalModule(@Nonnull String module) {
        return module.startsWith("node:") ? module.substring("node:".length()) : module;
    }

    // -------------------------------------------------------------------------
    // Statement collection
    // -------------------------------------------------------------------------

    private void walk(
            @Nonnull ParseTree node,
            @Nonnull JavaScriptScope scope,
            @Nonnull List<JavaScriptTree> sink,
            @Nonnull List<JavaScriptBlockTree> blocks) {
        if (node instanceof TypeScriptParser.FunctionBodyContext body) {
            walkAsOwnBlock(body, scope, blocks);
        } else if (node instanceof TypeScriptParser.ArrowFunctionBodyContext arrow
                && arrow.singleExpression() != null) {
            walkAsOwnBlock(arrow, scope, blocks);
        } else if (node instanceof TypeScriptParser.BlockContext) {
            walkChildren(node, new JavaScriptScope(scope), sink, blocks);
        } else if (node instanceof TypeScriptParser.VariableDeclarationContext declaration) {
            declare(declaration, scope, sink, blocks);
        } else if (node instanceof TypeScriptParser.AssignmentExpressionContext assignment) {
            assign(assignment, scope, sink, blocks);
        } else if (node instanceof TypeScriptParser.ArgumentsExpressionContext
                || node instanceof TypeScriptParser.NewExpressionContext) {
            sink.add(
                    convertCall(
                            (TypeScriptParser.SingleExpressionContext) node, null, scope, sink));
            walkFunctionBodies(node, scope, blocks);
        } else {
            walkChildren(node, scope, sink, blocks);
        }
    }

    private void walkChildren(
            @Nonnull ParseTree node,
            @Nonnull JavaScriptScope scope,
            @Nonnull List<JavaScriptTree> sink,
            @Nonnull List<JavaScriptBlockTree> blocks) {
        for (int i = 0; i < node.getChildCount(); i++) {
            walk(node.getChild(i), scope, sink, blocks);
        }
    }

    /** A function body is its own top-level block, chained to the scope it was declared in. */
    private void walkAsOwnBlock(
            @Nonnull ParserRuleContext body,
            @Nonnull JavaScriptScope outer,
            @Nonnull List<JavaScriptBlockTree> blocks) {
        JavaScriptScope functionScope = new JavaScriptScope(outer);
        List<JavaScriptTree> statements = new ArrayList<>();
        walkChildren(body, functionScope, statements, blocks);
        Token start = body.getStart();
        blocks.add(
                new JavaScriptBlockTree(
                        start.getLine(), start.getCharPositionInLine(), statements, functionScope));
    }

    /** Finds function bodies nested in an already-converted expression and walks them as blocks. */
    private void walkFunctionBodies(
            @Nonnull ParseTree node,
            @Nonnull JavaScriptScope scope,
            @Nonnull List<JavaScriptBlockTree> blocks) {
        if (node instanceof TypeScriptParser.FunctionBodyContext
                || (node instanceof TypeScriptParser.ArrowFunctionBodyContext arrow
                        && arrow.singleExpression() != null)) {
            walk(node, scope, new ArrayList<>(), blocks);
            return;
        }
        for (int i = 0; i < node.getChildCount(); i++) {
            walkFunctionBodies(node.getChild(i), scope, blocks);
        }
    }

    private void declare(
            @Nonnull TypeScriptParser.VariableDeclarationContext declaration,
            @Nonnull JavaScriptScope scope,
            @Nonnull List<JavaScriptTree> sink,
            @Nonnull List<JavaScriptBlockTree> blocks) {
        TypeScriptParser.SingleExpressionContext init = initializerOf(declaration);
        TypeScriptParser.IdentifierOrKeyWordContext nameNode = declaration.identifierOrKeyWord();
        if (nameNode == null || init == null) {
            if (nameNode != null) {
                scope.define(
                        nameNode.getText(),
                        new JavaScriptVariable(
                                nameNode.getText(),
                                null,
                                0,
                                kindOf(declaration),
                                declaration.getStart().getLine()));
            }
            if (init != null) {
                walkChildren(init, scope, sink, blocks);
            }
            return;
        }
        String name = nameNode.getText();
        JavaScriptTree value = convertValue(init, name, scope, sink);
        scope.define(
                name,
                new JavaScriptVariable(
                        name, value, 1, kindOf(declaration), declaration.getStart().getLine()));
        walkFunctionBodies(init, scope, blocks);
    }

    private void assign(
            @Nonnull TypeScriptParser.AssignmentExpressionContext assignment,
            @Nonnull JavaScriptScope scope,
            @Nonnull List<JavaScriptTree> sink,
            @Nonnull List<JavaScriptBlockTree> blocks) {
        TypeScriptParser.SingleExpressionContext target = unwrap(assignment.singleExpression(0));
        String targetName = target.getText();
        JavaScriptTree value =
                convertValue(assignment.singleExpression(1), targetName, scope, sink);
        if (target instanceof TypeScriptParser.IdentifierExpressionContext) {
            scope.recordAssignment(targetName, value);
        }
        walkFunctionBodies(assignment.singleExpression(1), scope, blocks);
    }

    /**
     * Converts the right-hand side of a declaration/assignment. A call is emitted as a statement
     * assigned to {@code assignedName}, which is what makes it a trackable creation.
     */
    @Nonnull
    private JavaScriptTree convertValue(
            @Nonnull TypeScriptParser.SingleExpressionContext expression,
            @Nonnull String assignedName,
            @Nonnull JavaScriptScope scope,
            @Nonnull List<JavaScriptTree> sink) {
        TypeScriptParser.SingleExpressionContext unwrapped = unwrap(expression);
        if (unwrapped instanceof TypeScriptParser.ArgumentsExpressionContext
                || unwrapped instanceof TypeScriptParser.NewExpressionContext) {
            JavaScriptCallTree call = convertCall(unwrapped, assignedName, scope, sink);
            sink.add(call);
            return call;
        }
        return convertExpression(unwrapped, scope, sink);
    }

    // -------------------------------------------------------------------------
    // Expression conversion
    // -------------------------------------------------------------------------

    @Nonnull
    private JavaScriptCallTree convertCall(
            @Nonnull TypeScriptParser.SingleExpressionContext expression,
            @Nullable String assignedName,
            @Nonnull JavaScriptScope scope,
            @Nonnull List<JavaScriptTree> sink) {
        Token start = expression.getStart();
        if (expression instanceof TypeScriptParser.NewExpressionContext creation) {
            String typeName = creation.singleExpression().getText();
            List<JavaScriptTree> args = convertArguments(creation.arguments(), scope, sink);
            return new JavaScriptCallTree(
                    start.getLine(),
                    start.getCharPositionInLine(),
                    typeName,
                    "<init>",
                    args,
                    true,
                    assignedName,
                    scope);
        }
        TypeScriptParser.ArgumentsExpressionContext call =
                (TypeScriptParser.ArgumentsExpressionContext) expression;
        TypeScriptParser.SingleExpressionContext callee = unwrap(call.singleExpression());
        String receiver;
        String method;
        if (callee instanceof TypeScriptParser.MemberDotExpressionContext member) {
            method = member.identifierName().getText();
            receiver = receiverOf(unwrap(member.singleExpression()), scope, sink);
        } else if (callee instanceof TypeScriptParser.IdentifierExpressionContext identifier) {
            String name = identifier.identifierName().getText();
            BoundMember bound = boundMembers.get(name);
            receiver = bound == null ? "" : bound.module();
            method = bound == null ? name : bound.member();
        } else {
            receiver = "";
            method = callee.getText();
        }
        List<JavaScriptTree> args = convertArguments(call.arguments(), scope, sink);
        return new JavaScriptCallTree(
                start.getLine(),
                start.getCharPositionInLine(),
                receiver,
                method,
                args,
                false,
                assignedName,
                scope);
    }

    /**
     * Returns the receiver name for a call. When the receiver is itself a call (a chain), that call
     * is emitted first under a synthetic name and the synthetic name is returned.
     */
    @Nonnull
    private String receiverOf(
            @Nonnull TypeScriptParser.SingleExpressionContext target,
            @Nonnull JavaScriptScope scope,
            @Nonnull List<JavaScriptTree> sink) {
        if (target instanceof TypeScriptParser.ArgumentsExpressionContext
                || target instanceof TypeScriptParser.NewExpressionContext) {
            String synthetic = "$chain" + chainCounter++;
            JavaScriptCallTree inner = convertCall(target, synthetic, scope, sink);
            sink.add(inner);
            scope.define(
                    synthetic,
                    new JavaScriptVariable(
                            synthetic,
                            inner,
                            1,
                            JavaScriptVariable.Kind.CHAIN,
                            target.getStart().getLine()));
            return synthetic;
        }
        if (target instanceof TypeScriptParser.IdentifierExpressionContext identifier) {
            String name = identifier.identifierName().getText();
            return moduleAliases.getOrDefault(name, name);
        }
        return target.getText();
    }

    @Nonnull
    private List<JavaScriptTree> convertArguments(
            @Nullable TypeScriptParser.ArgumentsContext arguments,
            @Nonnull JavaScriptScope scope,
            @Nonnull List<JavaScriptTree> sink) {
        List<JavaScriptTree> result = new ArrayList<>();
        if (arguments == null || arguments.argumentList() == null) {
            return result;
        }
        for (TypeScriptParser.ArgumentContext argument : arguments.argumentList().argument()) {
            if (argument.Ellipsis() != null || argument.singleExpression() == null) {
                Token start = argument.getStart();
                result.add(
                        new JavaScriptUnknownTree(
                                start.getLine(),
                                start.getCharPositionInLine(),
                                argument.getText()));
            } else {
                result.add(convertExpression(unwrap(argument.singleExpression()), scope, sink));
            }
        }
        return result;
    }

    @Nonnull
    private JavaScriptTree convertExpression(
            @Nonnull TypeScriptParser.SingleExpressionContext expression,
            @Nonnull JavaScriptScope scope,
            @Nonnull List<JavaScriptTree> sink) {
        Token start = expression.getStart();
        int line = start.getLine();
        int column = start.getCharPositionInLine();
        if (expression instanceof TypeScriptParser.LiteralExpressionContext literal) {
            JavaScriptTree converted = convertLiteral(literal.literal(), line, column);
            if (converted != null) {
                return converted;
            }
        } else if (expression instanceof TypeScriptParser.IdentifierExpressionContext identifier) {
            return new JavaScriptIdentifierTree(
                    line, column, identifier.identifierName().getText(), scope);
        } else if (expression instanceof TypeScriptParser.MemberDotExpressionContext member) {
            String qualifier = member.singleExpression().getText();
            if (qualifier.matches("[\\w$.]+")) {
                return new JavaScriptMemberTree(
                        line, column, qualifier, member.identifierName().getText());
            }
        } else if (expression instanceof TypeScriptParser.ArgumentsExpressionContext
                || expression instanceof TypeScriptParser.NewExpressionContext) {
            JavaScriptCallTree call = convertCall(expression, null, scope, sink);
            sink.add(call);
            return call;
        }
        return new JavaScriptUnknownTree(line, column, expression.getText());
    }

    @Nullable private static JavaScriptTree convertLiteral(
            @Nonnull TypeScriptParser.LiteralContext literal, int line, int column) {
        if (literal.StringLiteral() != null) {
            return new JavaScriptLiteralTree(
                    line,
                    column,
                    JavaScriptLiteralTree.Kind.STRING,
                    unquote(literal.StringLiteral().getText()));
        }
        if (literal.templateStringLiteral() != null) {
            String raw = literal.templateStringLiteral().getText();
            if (raw.startsWith("`") && raw.endsWith("`") && !raw.contains("${")) {
                return new JavaScriptLiteralTree(
                        line,
                        column,
                        JavaScriptLiteralTree.Kind.STRING,
                        raw.substring(1, raw.length() - 1));
            }
            return null;
        }
        if (literal.numericLiteral() != null) {
            return new JavaScriptLiteralTree(
                    line, column, JavaScriptLiteralTree.Kind.NUMBER, literal.getText());
        }
        if (literal.BooleanLiteral() != null) {
            return new JavaScriptLiteralTree(
                    line, column, JavaScriptLiteralTree.Kind.BOOLEAN, literal.getText());
        }
        if (literal.NullLiteral() != null) {
            return new JavaScriptLiteralTree(
                    line, column, JavaScriptLiteralTree.Kind.NULL, literal.getText());
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /** Strips wrappers that do not change which value an expression denotes. */
    @Nonnull
    private static TypeScriptParser.SingleExpressionContext unwrap(
            @Nonnull TypeScriptParser.SingleExpressionContext expression) {
        TypeScriptParser.SingleExpressionContext current = expression;
        while (true) {
            if (current instanceof TypeScriptParser.ParenthesizedExpressionContext paren
                    && paren.expressionSequence().singleExpression().size() == 1) {
                current = paren.expressionSequence().singleExpression(0);
            } else if (current instanceof TypeScriptParser.AwaitExpressionContext await) {
                current = await.singleExpression();
            } else if (current instanceof TypeScriptParser.NonNullAssertionExpressionContext nn) {
                current = nn.singleExpression();
            } else if (current instanceof TypeScriptParser.CastAsExpressionContext cast) {
                current = cast.singleExpression();
            } else {
                return current;
            }
        }
    }

    @Nullable private static TypeScriptParser.SingleExpressionContext initializerOf(
            @Nonnull TypeScriptParser.VariableDeclarationContext declaration) {
        List<TypeScriptParser.SingleExpressionContext> expressions = declaration.singleExpression();
        return expressions.isEmpty() ? null : expressions.get(expressions.size() - 1);
    }

    @Nonnull
    private static JavaScriptVariable.Kind kindOf(
            @Nonnull TypeScriptParser.VariableDeclarationContext declaration) {
        ParseTree parent = declaration.getParent();
        while (parent != null && !(parent instanceof TypeScriptParser.VariableStatementContext)) {
            parent = parent.getParent();
        }
        if (parent instanceof TypeScriptParser.VariableStatementContext statement
                && statement.varModifier() != null
                && "const".equals(statement.varModifier().getText())) {
            return JavaScriptVariable.Kind.CONST;
        }
        return JavaScriptVariable.Kind.MUTABLE;
    }

    @Nonnull
    private static String unquote(@Nonnull String quoted) {
        if (quoted.length() >= 2) {
            char first = quoted.charAt(0);
            char last = quoted.charAt(quoted.length() - 1);
            if ((first == '\'' || first == '"' || first == '`') && first == last) {
                return quoted.substring(1, quoted.length() - 1);
            }
        }
        return quoted;
    }
}
