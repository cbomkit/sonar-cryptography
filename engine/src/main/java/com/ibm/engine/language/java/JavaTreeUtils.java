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
package com.ibm.engine.language.java;

import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.AssignmentExpressionTree;
import org.sonar.plugins.java.api.tree.ExpressionTree;
import org.sonar.plugins.java.api.tree.IdentifierTree;
import org.sonar.plugins.java.api.tree.MemberSelectExpressionTree;
import org.sonar.plugins.java.api.tree.MethodInvocationTree;
import org.sonar.plugins.java.api.tree.MethodTree;
import org.sonar.plugins.java.api.tree.ParenthesizedTree;
import org.sonar.plugins.java.api.tree.Tree;
import org.sonar.plugins.java.api.tree.VariableTree;

/**
 * Tree helpers built solely on the public sonar-java API ({@code org.sonar.plugins.java.api}).
 *
 * <p>Internal sonar-java classes ({@code org.sonar.java.*}) are not exported to other plugins'
 * classloaders, so the engine must not reference them.
 */
public final class JavaTreeUtils {

    private JavaTreeUtils() {
        // utility class
    }

    /** Returns the identifier naming the invoked method, e.g. {@code foo} in {@code a.b.foo()}. */
    @Nonnull
    public static IdentifierTree methodName(@Nonnull MethodInvocationTree invocation) {
        final ExpressionTree select = invocation.methodSelect();
        if (select instanceof MemberSelectExpressionTree memberSelect) {
            return memberSelect.identifier();
        }
        return (IdentifierTree) select;
    }

    /** Returns the closest enclosing method or constructor, or {@code null} if there is none. */
    @Nullable public static MethodTree getEnclosingMethod(@Nonnull Tree tree) {
        Tree current = tree.parent();
        while (current != null && !current.is(Tree.Kind.METHOD, Tree.Kind.CONSTRUCTOR)) {
            current = current.parent();
        }
        return (MethodTree) current;
    }

    /**
     * Returns the symbol the expression is assigned to, if its direct parent is an assignment
     * ({@code x = expr}, {@code this.x = expr}) or a variable declaration ({@code T x = expr}).
     */
    @Nonnull
    public static Optional<Symbol> getAssignedSymbol(@Nonnull ExpressionTree expression) {
        final Tree parent = expression.parent();
        if (parent instanceof AssignmentExpressionTree assignment
                && parent.is(Tree.Kind.ASSIGNMENT)) {
            return extractIdentifierSymbol(assignment.variable());
        }
        if (parent instanceof VariableTree variable) {
            return Optional.of(variable.simpleName().symbol());
        }
        return Optional.empty();
    }

    /**
     * Returns the symbol of a plain identifier ({@code x}) or of a field accessed through {@code
     * this} / {@code super} ({@code this.x}), ignoring surrounding parentheses.
     */
    @Nonnull
    public static Optional<Symbol> extractIdentifierSymbol(@Nonnull ExpressionTree expression) {
        final ExpressionTree tree = skipParentheses(expression);
        if (tree instanceof IdentifierTree identifier) {
            return Optional.of(identifier.symbol());
        }
        if (tree instanceof MemberSelectExpressionTree memberSelect
                && isSelectOnThisOrSuper(memberSelect)) {
            return Optional.of(memberSelect.identifier().symbol());
        }
        return Optional.empty();
    }

    /** Strips any number of enclosing parentheses from the expression. */
    @Nonnull
    public static ExpressionTree skipParentheses(@Nonnull ExpressionTree expression) {
        ExpressionTree current = expression;
        while (current instanceof ParenthesizedTree parenthesized) {
            current = parenthesized.expression();
        }
        return current;
    }

    private static boolean isSelectOnThisOrSuper(@Nonnull MemberSelectExpressionTree select) {
        if (select.expression() instanceof IdentifierTree owner) {
            final String name = owner.name();
            return "this".equalsIgnoreCase(name) || "super".equalsIgnoreCase(name);
        }
        return false;
    }
}
