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
import com.ibm.engine.language.csharp.tree.CSharpBlockTree;
import com.ibm.engine.language.csharp.tree.CSharpIdentifierTree;
import com.ibm.engine.language.csharp.tree.CSharpLiteralTree;
import com.ibm.engine.language.csharp.tree.CSharpMemberAccessTree;
import com.ibm.engine.language.csharp.tree.CSharpMethodInvocationTree;
import com.ibm.engine.language.csharp.tree.CSharpObjectCreationTree;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.antlr.v4.runtime.Token;
import org.antlr.v4.runtime.tree.ParseTree;

/**
 * Converts an ANTLR4 C# parse tree to the language-agnostic {@link CSharpTree} hierarchy.
 *
 * <p>This visitor walks the ANTLR parse tree to find method bodies ({@link
 * CSharpParser.BlockContext}) and extracts the following patterns from each body:
 *
 * <ul>
 *   <li>Static factory calls: {@code Aes.Create()}, {@code RSA.Create(2048)}
 *   <li>Constructor calls: {@code new AesManaged()}, {@code new AesGcm(key)}
 * </ul>
 *
 * <p>Each method body is returned as a {@link CSharpBlockTree} containing the detected invocations,
 * ready to be handed to the detection engine.
 *
 * <p>The converter uses two ANTLR visitor layers:
 *
 * <ol>
 *   <li>Outer {@link CSharpTreeConverter} — walks the whole compilation unit and calls {@link
 *       #visitBlock} for every {@code { }} scope found.
 *   <li>Inner {@link StatementCollector} — collects method invocations and object creations within
 *       a single block, stopping at nested blocks so they are picked up by the outer visitor.
 * </ol>
 */
public final class CSharpTreeConverter extends CSharpParserBaseVisitor<Void> {

    private final List<CSharpBlockTree> bodies = new ArrayList<>();

    /**
     * Extracts all method bodies from the compilation unit.
     *
     * @param root the root parse tree node
     * @return list of block trees, one per method/constructor/lambda body found
     */
    @Nonnull
    public List<CSharpBlockTree> extractMethodBodies(
            @Nonnull CSharpParser.Compilation_unitContext root) {
        visit(root);
        return Collections.unmodifiableList(bodies);
    }

    /**
     * Called for every {@code { ... }} block in the parse tree.
     *
     * <p>Collects the invocations at this block's immediate statement level (via {@link
     * StatementCollector}), adds the resulting {@link CSharpBlockTree} to the list, then recurses
     * into children so nested blocks are discovered by subsequent {@link #visitBlock} calls.
     */
    @Override
    public Void visitBlock(CSharpParser.BlockContext ctx) {
        StatementCollector collector = new StatementCollector();
        // Visit each child of the block through the collector (not the block itself, to avoid
        // triggering StatementCollector.visitBlock which stops at nested blocks)
        for (int i = 0; i < ctx.getChildCount(); i++) {
            collector.visit(ctx.getChild(i));
        }
        bodies.add(
                new CSharpBlockTree(
                        ctx.getStart().getLine(),
                        ctx.getStart().getCharPositionInLine(),
                        collector.getStatements()));
        // Recurse to discover nested blocks (lambdas, local functions, etc.)
        visitChildren(ctx);
        return null;
    }

    // -----------------------------------------------------------------------
    // Inner visitor: collects invocations within a single block level
    // -----------------------------------------------------------------------

    /**
     * Collects method invocations and object creations from a single block, stopping at nested
     * {@link CSharpParser.BlockContext} nodes so they are handled by the outer visitor.
     */
    private static final class StatementCollector extends CSharpParserBaseVisitor<Void> {

        private final List<CSharpTree> statements = new ArrayList<>();

        /**
         * Set to the LHS identifier before descending into a {@code local_variable_declarator}'s
         * initializer. Consumed (set back to null) by {@link #visitPrimary_expression} so it is
         * applied to exactly the first (outermost) primary_expression in the initializer.
         */
        @Nullable private String pendingAssignedIdentifier = null;

        @Nonnull
        List<CSharpTree> getStatements() {
            return Collections.unmodifiableList(statements);
        }

        /** Stop at nested blocks — they become separate {@link CSharpBlockTree} entries. */
        @Override
        public Void visitBlock(CSharpParser.BlockContext ctx) {
            return null;
        }

        /**
         * Captures the variable name from {@code var x = Expr()} so that the emitted tree node gets
         * its {@code assignedIdentifier} populated for later symbol tracking.
         */
        @Override
        public Void visitLocal_variable_declarator(
                CSharpParser.Local_variable_declaratorContext ctx) {
            if (ctx.identifier() != null && ctx.local_variable_initializer() != null) {
                pendingAssignedIdentifier = ctx.identifier().getText();
            }
            try {
                return visitChildren(ctx);
            } finally {
                pendingAssignedIdentifier = null;
            }
        }

        /**
         * Handles property-setter assignments of the form {@code obj.Property = value}.
         *
         * <p>Emits a synthetic {@link CSharpMethodInvocationTree} with method name {@code
         * set_<Property>} (e.g. {@code set_Mode}) and the RHS as the sole argument. This mirrors
         * the underlying CLR semantics — C# properties compile to {@code get_X}/{@code set_X}
         * accessor methods. The synthetic node is then picked up by {@code isInvocationOnVariable}
         * + {@code withDependingDetectionRules} in the detection engine.
         *
         * <p>Stops recursion so that neither the LHS nor the RHS {@code primary_expression} nodes
         * are visited separately.
         */
        @Override
        public Void visitAssignment(CSharpParser.AssignmentContext ctx) {
            // Only handle simple assignment (=), not compound (+=, -=, etc.)
            if (ctx.assignment_operator() == null
                    || ctx.assignment_operator().ASSIGNMENT() == null) {
                return null;
            }

            // Find primary_expression inside the LHS unary_expression
            CSharpParser.Primary_expressionContext lhsPrimary =
                    findPrimaryExpression(ctx.unary_expression());
            if (lhsPrimary == null) {
                return null;
            }

            List<ParseTree> children = lhsPrimary.children;
            if (children == null || children.size() < 2) {
                return null;
            }

            CSharpParser.Primary_expression_startContext start =
                    lhsPrimary.primary_expression_start();
            if (!(start instanceof CSharpParser.SimpleNameExpressionContext simpleCtx)) {
                return null;
            }

            // LHS must be exactly: identifier.PropertyName — one member_access, no method
            // invocation
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

            // Convert RHS expression to the setter argument
            CSharpParser.ExpressionContext rhs = ctx.expression();
            if (rhs == null) {
                return null;
            }
            CSharpTree rhsTree = convertExpression(rhs);
            List<CSharpTree> args =
                    rhsTree != null ? Collections.singletonList(rhsTree) : Collections.emptyList();

            statements.add(
                    new CSharpMethodInvocationTree(
                            ctx.getStart().getLine(),
                            ctx.getStart().getCharPositionInLine(),
                            variableName,
                            setterName,
                            args,
                            null, // property setters are not themselves assigned to a variable
                            null)); // enclosingBlock set by CSharpBlockTree constructor

            return null; // do NOT visit children — prevents double-counting LHS / RHS nodes
        }

        /**
         * Converts the primary_expression and adds it to the statement list. Does NOT recurse
         * further to avoid double-counting nested primary_expressions. Consumes {@link
         * #pendingAssignedIdentifier} so it is applied to the outermost call only.
         */
        @Override
        public Void visitPrimary_expression(CSharpParser.Primary_expressionContext ctx) {
            String assignedId = pendingAssignedIdentifier;
            pendingAssignedIdentifier = null; // consume — prevents leaking to sibling expressions
            CSharpTree node = convertPrimaryExpression(ctx, assignedId);
            if (node != null) {
                statements.add(node);
            }
            return null;
        }

        // -----------------------------------------------------------------------
        // Primary expression conversion
        // -----------------------------------------------------------------------

        /**
         * Converts a primary_expression to a CSharpTree node.
         *
         * <p>Handled patterns:
         *
         * <ul>
         *   <li>{@code new AesManaged()} — objectCreationExpression start, no further parts
         *   <li>{@code Aes.Create()} — simpleNameExpression + member_access + method_invocation
         * </ul>
         */
        @Nullable private CSharpTree convertPrimaryExpression(
                @Nonnull CSharpParser.Primary_expressionContext ctx,
                @Nullable String assignedIdentifier) {
            CSharpParser.Primary_expression_startContext start = ctx.primary_expression_start();

            // Pattern: new AesManaged(), new AesGcm(key), etc.
            if (start instanceof CSharpParser.ObjectCreationExpressionContext objCreationCtx) {
                return convertObjectCreationFromStart(objCreationCtx, assignedIdentifier);
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
                    assignedIdentifier,
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
                @Nonnull CSharpParser.ObjectCreationExpressionContext objCreationCtx,
                @Nullable String assignedIdentifier) {
            // In v7 grammar, type_ is directly on ObjectCreationExpressionContext
            // (not nested inside object_creation_expression as in the old simplified grammar)
            CSharpParser.Type_Context typeCtx = objCreationCtx.type_();
            if (typeCtx == null) {
                return null;
            }
            String typeName = typeCtx.getText();
            // Strip generic type arguments for matching (e.g. "List<int>" → "List")
            int ltIdx = typeName.indexOf('<');
            if (ltIdx > 0) {
                typeName = typeName.substring(0, ltIdx);
            }

            // In v7, object_creation_expression holds (OPEN_PARENS argument_list? CLOSE_PARENS)
            // directly — there is no object_creation_args wrapper
            List<CSharpTree> args = Collections.emptyList();
            CSharpParser.Object_creation_expressionContext objExpr =
                    objCreationCtx.object_creation_expression();
            if (objExpr != null) {
                args = convertArgumentList(objExpr.argument_list());
            }

            return new CSharpObjectCreationTree(
                    objCreationCtx.getStart().getLine(),
                    objCreationCtx.getStart().getCharPositionInLine(),
                    typeName,
                    args,
                    assignedIdentifier,
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
            CSharpParser.Primary_expressionContext primaryExpr = findPrimaryExpression(expr);
            if (primaryExpr != null) {
                CSharpTree start = convertPrimaryExpressionStart(primaryExpr);
                if (start != null) {
                    return start;
                }
            }
            return createLeafFromText(text, expr.getStart());
        }

        /**
         * Walks an expression to find the first primary_expression child (handles intermediate
         * grammar rules before reaching primary).
         */
        @Nullable private CSharpParser.Primary_expressionContext findPrimaryExpression(
                @Nonnull ParseTree tree) {
            if (tree instanceof CSharpParser.Primary_expressionContext primary) {
                return primary;
            }
            for (int i = 0; i < tree.getChildCount(); i++) {
                CSharpParser.Primary_expressionContext found =
                        findPrimaryExpression(tree.getChild(i));
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

            if (start instanceof CSharpParser.LiteralExpressionContext literalCtx) {
                return convertLiteral(literalCtx.literal());
            }

            if (start instanceof CSharpParser.SimpleNameExpressionContext simpleCtx) {
                String name = simpleCtx.identifier().getText();
                List<ParseTree> children = ctx.children;
                if (children != null && children.size() >= 2) {
                    for (int i = 1; i < children.size(); i++) {
                        if (children.get(i)
                                instanceof CSharpParser.Member_accessContext memberCtx) {
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

        /** Last-resort fallback: creates a leaf node by inspecting the raw text. */
        @Nullable private CSharpTree createLeafFromText(@Nonnull String text, @Nullable Token startToken) {
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
                return new CSharpMemberAccessTree(line, col, typePart, memberPart);
            }
            return new CSharpIdentifierTree(line, col, text);
        }
    }
}
