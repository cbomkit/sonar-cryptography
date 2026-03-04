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
package com.ibm.plugin;

import com.ibm.engine.language.csharp.tree.CSharpBlockTree;
import com.ibm.engine.language.csharp.tree.CSharpIdentifierTree;
import com.ibm.engine.language.csharp.tree.CSharpLiteralTree;
import com.ibm.engine.language.csharp.tree.CSharpMemberAccessTree;
import com.ibm.engine.language.csharp.tree.CSharpMethodInvocationTree;
import com.ibm.engine.language.csharp.tree.CSharpObjectCreationTree;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.plugin.antlr.CSharpParser;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.antlr.v4.runtime.Token;
import org.antlr.v4.runtime.tree.ParseTree;
import org.antlr.v4.runtime.tree.TerminalNode;

/**
 * Converts an ANTLR4 C# parse tree to the language-agnostic {@link CSharpTree} hierarchy.
 *
 * <p>The converter walks the ANTLR parse tree to find method bodies ({@link
 * CSharpParser.BlockContext}) and extracts the following patterns from each body:
 *
 * <ul>
 *   <li>Static factory calls: {@code Aes.Create()}, {@code RSA.Create(2048)}
 *   <li>Constructor calls: {@code new AesManaged()}, {@code new AesGcm(key)}
 * </ul>
 *
 * <p>Each method body is returned as a {@link CSharpBlockTree} containing the detected invocations,
 * ready to be handed to the detection engine.
 */
public final class CSharpTreeConverter {

    public CSharpTreeConverter() {
        // nothing
    }

    /**
     * Extracts all method bodies from the compilation unit.
     *
     * @param root the root parse tree node
     * @return list of block trees, one per method/constructor body found
     */
    @Nonnull
    public List<CSharpBlockTree> extractMethodBodies(
            @Nonnull CSharpParser.Compilation_unitContext root) {
        List<CSharpBlockTree> bodies = new ArrayList<>();
        collectBlocks(root, bodies);
        return bodies;
    }

    /** Recursively walks the tree to find all {@link CSharpParser.BlockContext} nodes. */
    private void collectBlocks(@Nonnull ParseTree tree, @Nonnull List<CSharpBlockTree> bodies) {
        if (tree instanceof CSharpParser.BlockContext block) {
            bodies.add(convertBlock(block));
            // Nested blocks (lambdas, local functions) are added separately via the recursion below
        }
        for (int i = 0; i < tree.getChildCount(); i++) {
            collectBlocks(tree.getChild(i), bodies);
        }
    }

    /** Converts a {@link CSharpParser.BlockContext} to a {@link CSharpBlockTree}. */
    @Nonnull
    private CSharpBlockTree convertBlock(@Nonnull CSharpParser.BlockContext ctx) {
        List<CSharpTree> statements = new ArrayList<>();
        // Iterate over children directly — passing ctx itself would trigger the nested-block guard
        for (int i = 0; i < ctx.getChildCount(); i++) {
            collectInvocations(ctx.getChild(i), statements, true);
        }
        return new CSharpBlockTree(
                ctx.getStart().getLine(),
                ctx.getStart().getCharPositionInLine(),
                Collections.unmodifiableList(statements));
    }

    /**
     * Walks the subtree collecting method invocations and object creations.
     *
     * @param isTopBlock if true, stops at nested {@link CSharpParser.BlockContext} (those are
     *     separate method bodies handled by the outer loop)
     */
    private void collectInvocations(
            @Nonnull ParseTree tree, @Nonnull List<CSharpTree> statements, boolean isTopBlock) {
        if (tree instanceof TerminalNode) {
            return;
        }
        // Stop at nested blocks — they are independent method bodies
        if (isTopBlock && tree instanceof CSharpParser.BlockContext) {
            return;
        }

        if (tree instanceof CSharpParser.Primary_expressionContext primaryExpr) {
            CSharpTree node = convertPrimaryExpression(primaryExpr);
            if (node != null) {
                statements.add(node);
            }
            // Do NOT recurse further into this primary_expression to avoid double-counting
            return;
        }

        for (int i = 0; i < tree.getChildCount(); i++) {
            collectInvocations(tree.getChild(i), statements, isTopBlock);
        }
    }

    // -----------------------------------------------------------------------
    // Primary expression conversion
    // -----------------------------------------------------------------------

    /**
     * Converts a primary_expression to a CSharpTree node.
     *
     * <p>Grammar (simplified):
     *
     * <pre>
     * primary_expression
     *     : pe=primary_expression_start bracket_expression*
     *       ( (member_access | method_invocation | ...) bracket_expression* )*
     *     ;
     * </pre>
     *
     * <p>Handled patterns:
     *
     * <ul>
     *   <li>{@code new AesManaged()} — objectCreationExpression start, no further parts
     *   <li>{@code Aes.Create()} — simpleNameExpression + member_access + method_invocation
     * </ul>
     */
    @Nullable private CSharpTree convertPrimaryExpression(
            @Nonnull CSharpParser.Primary_expressionContext ctx) {
        CSharpParser.Primary_expression_startContext start = ctx.primary_expression_start();

        // Pattern: new AesManaged(), new AesGcm(key), etc.
        if (start instanceof CSharpParser.ObjectCreationExpressionContext objCreationCtx) {
            return convertObjectCreationFromStart(objCreationCtx);
        }

        // Pattern: Aes.Create(), RSA.Create(2048), SHA256.Create()
        // Children of primary_expression in order: [start, ...parts...]
        List<ParseTree> children = ctx.children;
        if (children == null || children.size() < 3) {
            return null;
        }

        // Find the last method_invocation in the child list
        int methodInvIdx = -1;
        for (int i = children.size() - 1; i >= 1; i--) {
            if (children.get(i) instanceof CSharpParser.Method_invocationContext) {
                methodInvIdx = i;
                break;
            }
        }
        if (methodInvIdx < 0) {
            return null;
        }

        // Find the member_access immediately preceding the method_invocation
        int memberAccessIdx = -1;
        for (int i = methodInvIdx - 1; i >= 1; i--) {
            if (children.get(i) instanceof CSharpParser.Member_accessContext) {
                memberAccessIdx = i;
                break;
            }
            // bracket_expressions can appear between member_access and method_invocation
            if (!(children.get(i) instanceof CSharpParser.Bracket_expressionContext)) {
                break;
            }
        }
        if (memberAccessIdx < 0) {
            return null;
        }

        CSharpParser.Member_accessContext memberAccess =
                (CSharpParser.Member_accessContext) children.get(memberAccessIdx);
        CSharpParser.Method_invocationContext methodInv =
                (CSharpParser.Method_invocationContext) children.get(methodInvIdx);

        String methodName = memberAccess.identifier().getText();
        String objectTypeName = resolveObjectTypeName(start, children, memberAccessIdx);
        List<CSharpTree> args = convertArgumentList(methodInv.argument_list());

        return new CSharpMethodInvocationTree(
                ctx.getStart().getLine(),
                ctx.getStart().getCharPositionInLine(),
                objectTypeName,
                methodName,
                args,
                null,
                null);
    }

    /**
     * Resolves the object type name for a method invocation chain.
     *
     * <p>For {@code Aes.Create()}: start = "Aes", memberAccessIdx = 1 → "Aes". For {@code
     * foo.Aes.Create()}: the member_access before the last gives "Aes".
     */
    @Nonnull
    private String resolveObjectTypeName(
            @Nonnull CSharpParser.Primary_expression_startContext start,
            @Nonnull List<ParseTree> children,
            int memberAccessIdx) {
        // Check if there's a preceding member_access (chained call)
        for (int i = memberAccessIdx - 1; i >= 1; i--) {
            if (children.get(i) instanceof CSharpParser.Member_accessContext prevMember) {
                return prevMember.identifier().getText();
            }
        }
        // Simple case: start holds the receiver type name
        if (start instanceof CSharpParser.SimpleNameExpressionContext simpleCtx) {
            return simpleCtx.identifier().getText();
        }
        return start.getText();
    }

    /** Handles the {@code new Type(...)} pattern from an objectCreationExpression start. */
    @Nullable private CSharpTree convertObjectCreationFromStart(
            @Nonnull CSharpParser.ObjectCreationExpressionContext objCreationCtx) {
        // Grammar: NEW (object_creation_expression | ...) #objectCreationExpression
        CSharpParser.Object_creation_expressionContext objExpr =
                objCreationCtx.object_creation_expression();
        if (objExpr == null) {
            return null;
        }

        // type_ rule — getText() gives "AesManaged", "AesGcm", etc.
        CSharpParser.Type_Context typeCtx = objExpr.type_();
        if (typeCtx == null) {
            return null;
        }
        String typeName = typeCtx.getText();
        // Strip generic type arguments for matching (e.g. "List<int>" → "List")
        int ltIdx = typeName.indexOf('<');
        if (ltIdx > 0) {
            typeName = typeName.substring(0, ltIdx);
        }

        // Arguments from object_creation_args (wraps the '(' argument_list? ')')
        List<CSharpTree> args = Collections.emptyList();
        CSharpParser.Object_creation_argsContext argsCtx = objExpr.object_creation_args();
        if (argsCtx != null) {
            args = convertArgumentList(argsCtx.argument_list());
        }

        return new CSharpObjectCreationTree(
                objExpr.getStart().getLine(),
                objExpr.getStart().getCharPositionInLine(),
                typeName,
                args,
                null,
                null);
    }

    // -----------------------------------------------------------------------
    // Argument conversion
    // -----------------------------------------------------------------------

    @Nonnull
    private List<CSharpTree> convertArgumentList(
            @Nullable CSharpParser.Argument_listContext argListCtx) {
        if (argListCtx == null) {
            return Collections.emptyList();
        }
        List<CSharpTree> args = new ArrayList<>();
        for (CSharpParser.ArgumentContext arg : argListCtx.argument()) {
            CSharpTree argTree = convertArgument(arg);
            if (argTree != null) {
                args.add(argTree);
            }
        }
        return Collections.unmodifiableList(args);
    }

    @Nullable private CSharpTree convertArgument(@Nonnull CSharpParser.ArgumentContext arg) {
        CSharpParser.ExpressionContext expr = arg.expression();
        if (expr == null) {
            return null;
        }
        return convertExpression(expr);
    }

    @Nullable private CSharpTree convertExpression(@Nonnull CSharpParser.ExpressionContext expr) {
        String text = expr.getText();
        if (text == null || text.isEmpty()) {
            return null;
        }
        // Delegate to primary_expression if present
        CSharpParser.Primary_expressionContext primaryExpr = findPrimaryExpression(expr);
        if (primaryExpr != null) {
            CSharpTree start = convertPrimaryExpressionStart(primaryExpr);
            if (start != null) {
                return start;
            }
        }
        // Fallback: use text content to create simple tree nodes
        return createLeafFromText(text, expr.getStart());
    }

    /**
     * Walks an expression to find the first primary_expression child (handles the case where the
     * expression rule delegates through several intermediate rules before reaching primary).
     */
    @Nullable private CSharpParser.Primary_expressionContext findPrimaryExpression(@Nonnull ParseTree tree) {
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

    /** Converts a primary_expression to its simplest leaf form (for argument extraction). */
    @Nullable private CSharpTree convertPrimaryExpressionStart(
            @Nonnull CSharpParser.Primary_expressionContext ctx) {
        CSharpParser.Primary_expression_startContext start = ctx.primary_expression_start();

        // Literal: INTEGER_LITERAL, REAL_LITERAL, string, etc.
        if (start instanceof CSharpParser.LiteralExpressionContext literalCtx) {
            return convertLiteral(literalCtx.literal());
        }

        // Simple name (identifier or member access like HashAlgorithmName.SHA256)
        if (start instanceof CSharpParser.SimpleNameExpressionContext simpleCtx) {
            String name = simpleCtx.identifier().getText();
            // Check for member access parts (e.g. HashAlgorithmName.SHA256)
            List<ParseTree> children = ctx.children;
            if (children != null && children.size() >= 2) {
                // Look for a member access part
                for (int i = 1; i < children.size(); i++) {
                    if (children.get(i) instanceof CSharpParser.Member_accessContext memberCtx) {
                        // Type.Member → CSharpMemberAccessTree
                        return new CSharpMemberAccessTree(
                                ctx.getStart().getLine(),
                                ctx.getStart().getCharPositionInLine(),
                                name,
                                memberCtx.identifier().getText());
                    }
                }
            }
            return new CSharpIdentifierTree(
                    ctx.getStart().getLine(), ctx.getStart().getCharPositionInLine(), name);
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
            // Strip surrounding quotes
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
        if (literalCtx.NULL() != null) {
            return new CSharpLiteralTree(line, col, CSharpLiteralTree.Kind.NULL, "null");
        }
        return new CSharpLiteralTree(line, col, CSharpLiteralTree.Kind.STRING, text);
    }

    /** Last-resort fallback: creates a leaf node by inspecting the raw text. */
    @Nullable private CSharpTree createLeafFromText(@Nonnull String text, @Nullable Token startToken) {
        int line = startToken != null ? startToken.getLine() : 0;
        int col = startToken != null ? startToken.getCharPositionInLine() : 0;

        if (text.isEmpty() || "null".equals(text)) {
            return null;
        }
        // Integer
        try {
            Integer.parseInt(text);
            return new CSharpLiteralTree(line, col, CSharpLiteralTree.Kind.INTEGER, text);
        } catch (NumberFormatException ignored) {
            // not integer
        }
        // String literal
        if ((text.startsWith("\"") && text.endsWith("\""))
                || (text.startsWith("@\"") && text.endsWith("\""))) {
            String value = text.replaceAll("^@?\"|\"+$", "");
            return new CSharpLiteralTree(line, col, CSharpLiteralTree.Kind.STRING, value);
        }
        // Enum-style member access (e.g. "HashAlgorithmName.SHA256")
        int dotIdx = text.lastIndexOf('.');
        if (dotIdx > 0) {
            String typePart = text.substring(0, dotIdx);
            String memberPart = text.substring(dotIdx + 1);
            return new CSharpMemberAccessTree(line, col, typePart, memberPart);
        }
        // Plain identifier
        return new CSharpIdentifierTree(line, col, text);
    }
}
