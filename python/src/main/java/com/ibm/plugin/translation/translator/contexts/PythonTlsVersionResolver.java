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
package com.ibm.plugin.translation.translator.contexts;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.symbols.Usage;
import org.sonar.plugins.python.api.tree.AssignmentStatement;
import org.sonar.plugins.python.api.tree.CallExpression;
import org.sonar.plugins.python.api.tree.Expression;
import org.sonar.plugins.python.api.tree.Name;
import org.sonar.plugins.python.api.tree.QualifiedExpression;
import org.sonar.plugins.python.api.tree.RegularArgument;
import org.sonar.plugins.python.api.tree.Tree;
import org.sonar.plugins.python.api.tree.Tuple;

/**
 * Reads the TLS version a standard library {@code ssl.SSLContext} is restricted to, starting from
 * the expression that hands the context to a library ({@code ssl_context=ctx} or {@code
 * tls_args=(ctx, host)}).
 *
 * <p>Two things in code state a version:
 *
 * <ul>
 *   <li>a version specific protocol constant, {@code ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)};
 *   <li>otherwise {@code ctx.minimum_version = ssl.TLSVersion.TLSv1_2}, set before the call. The
 *       reported version is then the lowest one the context permits.
 * </ul>
 *
 * <p>Nothing else is read. {@code create_default_context()}, {@code PROTOCOL_TLS_SERVER}, a {@code
 * maximum_version} alone, a computed value, a conditional assignment or contradicting assignments
 * leave the version unknown, because the one negotiated then depends on the platform.
 */
final class PythonTlsVersionResolver {

    private static final Set<String> VERSIONS = Set.of("TLSv1", "TLSv1_1", "TLSv1_2", "TLSv1_3");
    private static final String PROTOCOL_PREFIX = "PROTOCOL_";

    private PythonTlsVersionResolver() {}

    /** The version in the form {@code TLSv1.2}, or empty when the code does not state one. */
    @Nonnull
    static Optional<String> resolve(@Nonnull Tree argument) {
        Tree context = argument;
        Symbol contextSymbol = null;
        // `tls_args=args`, `args = (ctx, host)`, `ctx = ssl.SSLContext(...)`: at most two names
        for (int depth = 0; depth < 3; depth++) {
            if (context instanceof Tuple tuple && !tuple.elements().isEmpty()) {
                context = tuple.elements().get(0);
            }
            if (!(context instanceof Name name) || name.symbol() == null) {
                break;
            }
            contextSymbol = name.symbol();
            context = assignedValue(Objects.requireNonNull(contextSymbol));
            if (context == null || !(context instanceof Tuple || context instanceof Name)) {
                break;
            }
        }
        final Optional<String> fromConstructor = fromConstructor(context);
        if (fromConstructor.isPresent() || contextSymbol == null) {
            return fromConstructor.map(PythonTlsVersionResolver::format);
        }
        return fromMinimumVersion(contextSymbol, argument).map(PythonTlsVersionResolver::format);
    }

    @Nullable private static Expression assignedValue(@Nonnull Symbol symbol) {
        final List<Usage> bindings =
                symbol.usages().stream().filter(Usage::isBindingUsage).toList();
        if (bindings.size() != 1) {
            return null;
        }
        final AssignmentStatement assignment = assignmentOf(bindings.get(0).tree());
        return assignment == null ? null : assignment.assignedValue();
    }

    /** The assignment whose left hand side is exactly this tree, if there is one. */
    @Nullable private static AssignmentStatement assignmentOf(@Nonnull Tree target) {
        Tree parent = target.parent();
        if (parent != null && parent.is(Tree.Kind.EXPRESSION_LIST)) {
            parent = parent.parent();
        }
        if (parent instanceof AssignmentStatement assignment
                && assignment.lhsExpressions().size() == 1
                && assignment.lhsExpressions().get(0).expressions().size() == 1
                && assignment.lhsExpressions().get(0).expressions().get(0) == target) {
            return assignment;
        }
        return null;
    }

    @Nonnull
    private static Optional<String> fromConstructor(@Nullable Tree context) {
        if (!(context instanceof CallExpression call)
                || !"SSLContext".equals(lastName(call.callee()))) {
            return Optional.empty();
        }
        return call.arguments().stream()
                .filter(RegularArgument.class::isInstance)
                .map(RegularArgument.class::cast)
                .filter(
                        a ->
                                a.keywordArgument() == null
                                        || "protocol"
                                                .equals(
                                                        Objects.requireNonNull(a.keywordArgument())
                                                                .name()))
                .findFirst()
                .map(a -> lastName(a.expression()))
                .filter(n -> n.startsWith(PROTOCOL_PREFIX))
                .map(n -> n.substring(PROTOCOL_PREFIX.length()))
                .filter(VERSIONS::contains);
    }

    @Nonnull
    private static Optional<String> fromMinimumVersion(
            @Nonnull Symbol context, @Nonnull Tree argument) {
        final int callLine = argument.firstToken().line();
        final List<String> assigned =
                context.usages().stream()
                        .map(usage -> usage.tree().parent())
                        .filter(
                                parent ->
                                        parent instanceof QualifiedExpression attribute
                                                && "minimum_version"
                                                        .equals(attribute.name().name()))
                        .filter(attribute -> attribute.firstToken().line() < callLine)
                        .map(PythonTlsVersionResolver::assignmentOf)
                        .filter(Objects::nonNull)
                        .map(
                                assignment ->
                                        alwaysRunsBefore(assignment, argument)
                                                ? versionMember(assignment.assignedValue())
                                                : "")
                        .distinct()
                        .toList();
        // an unreadable value is "" and, like a second distinct one, leaves the version unknown
        return assigned.size() == 1
                ? Optional.of(assigned.get(0)).filter(VERSIONS::contains)
                : Optional.empty();
    }

    /**
     * Whether the statement sits in a block that also encloses the call. One inside an {@code if},
     * {@code try} or another function may not have run, so it says nothing certain.
     */
    private static boolean alwaysRunsBefore(@Nonnull Tree statement, @Nonnull Tree call) {
        for (Tree ancestor = call.parent(); ancestor != null; ancestor = ancestor.parent()) {
            if (ancestor == statement.parent()) {
                return true;
            }
        }
        return false;
    }

    /** {@code TLSv1_2} for {@code ssl.TLSVersion.TLSv1_2}, otherwise the empty string. */
    @Nonnull
    private static String versionMember(@Nonnull Expression value) {
        return value instanceof QualifiedExpression member
                        && "TLSVersion".equals(lastName(member.qualifier()))
                ? member.name().name()
                : "";
    }

    @Nonnull
    private static String lastName(@Nullable Tree expression) {
        if (expression instanceof Name name) {
            return name.name();
        }
        if (expression instanceof QualifiedExpression qualified) {
            return qualified.name().name();
        }
        return "";
    }

    @Nonnull
    private static String format(@Nonnull String member) {
        return member.replace('_', '.');
    }
}
