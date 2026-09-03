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

import com.ibm.engine.detection.IType;
import com.ibm.engine.detection.MatchContext;
import com.ibm.engine.language.ILanguageTranslation;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.java.model.ExpressionUtils;
import org.sonar.plugins.java.api.tree.Arguments;
import org.sonar.plugins.java.api.tree.ClassTree;
import org.sonar.plugins.java.api.tree.ExpressionTree;
import org.sonar.plugins.java.api.tree.IdentifierTree;
import org.sonar.plugins.java.api.tree.MemberSelectExpressionTree;
import org.sonar.plugins.java.api.tree.MethodInvocationTree;
import org.sonar.plugins.java.api.tree.NewClassTree;
import org.sonar.plugins.java.api.tree.Tree;

public class JavaLanguageTranslation implements ILanguageTranslation<Tree> {
    @Nonnull
    private static final Logger LOGGER = LoggerFactory.getLogger(JavaLanguageTranslation.class);

    @Nonnull
    @Override
    public Optional<String> getMethodName(
            @Nonnull MatchContext matchContext, @Nonnull Tree methodInvocation) {
        if (methodInvocation instanceof MethodInvocationTree methodInvocationTree) {
            return Optional.of(ExpressionUtils.methodName(methodInvocationTree).name());
        } else if (methodInvocation instanceof NewClassTree) {
            return Optional.of("<init>");
        }
        return Optional.empty();
    }

    @SuppressWarnings("java:S3776")
    @Nonnull
    @Override
    public Optional<IType> getInvokedObjectTypeString(
            @Nonnull MatchContext matchContext, @Nonnull Tree methodInvocation) {
        /*
         * ECJ Unable to resolve type junit.framework.TestCase
         *
         * Since the implementation of Hooks the MethodMatcher and therefore this function is used to
         * determine if a hook is invoked or not. Since Hooks persist over the whole scan (not deleted per module),
         * this check happens even on a module switch. Sonar-java uses ECJ to be able to resolve subtypes. This will
         * fail and throw when a hook-check is done, but the type is not part of the currently scanned module.
         * This failure would throw an error message into the logs, which could distract a user.
         *
         * Therefore, we excluded the subType check for hook invocation checks to stop the sonar-java-frontend from
         * throwing those errors.
         */
        if (methodInvocation instanceof MethodInvocationTree methodInvocationTree) {
            ExpressionTree expressionTree = methodInvocationTree.methodSelect();
            if (expressionTree instanceof MemberSelectExpressionTree memberSelectExpressionTree) {
                if (memberSelectExpressionTree.expression()
                        instanceof MethodInvocationTree methodInvocationTree1) {
                    return getMethodReturnTypeString(matchContext, methodInvocationTree1);
                }

                return Optional.of(memberSelectExpressionTree.expression())
                        .map(
                                tree ->
                                        string -> {
                                            if (matchContext.isHookContext()
                                                    || matchContext.objectShouldMatchExactTypes()) {
                                                return tree.symbolType().is(string);
                                            }
                                            return tree.symbolType().is(string)
                                                    || tree.symbolType().isSubtypeOf(string);
                                        });
            }

            if (methodInvocationTree.methodSymbol().type().isUnknown()) {
                return Optional.ofNullable(methodInvocationTree.methodSymbol().enclosingClass())
                        .map(
                                tree ->
                                        string -> {
                                            if (matchContext.isHookContext()
                                                    || matchContext.objectShouldMatchExactTypes()) {
                                                return tree.type().is(string);
                                            }
                                            return tree.type().is(string)
                                                    || tree.type().isSubtypeOf(string);
                                        });
            }
            return Optional.of(methodInvocationTree.methodSymbol())
                    .map(
                            tree ->
                                    string -> {
                                        if (matchContext.isHookContext()
                                                || matchContext.objectShouldMatchExactTypes()) {
                                            return tree.type().is(string);
                                        }
                                        return tree.type().is(string)
                                                || tree.type().isSubtypeOf(string);
                                    });
        } else if (methodInvocation instanceof NewClassTree newClassTree) {
            return Optional.of(newClassTree.identifier())
                    .map(
                            tree ->
                                    string -> {
                                        if (matchContext.isHookContext()
                                                || matchContext.objectShouldMatchExactTypes()) {
                                            return tree.symbolType().is(string);
                                        }
                                        return tree.symbolType().is(string)
                                                || tree.symbolType().isSubtypeOf(string);
                                    });
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<IType> getMethodReturnTypeString(
            @Nonnull MatchContext matchContext, @Nonnull Tree methodInvocation) {
        if (methodInvocation instanceof MethodInvocationTree methodInvocationTree) {
            return Optional.of(methodInvocationTree.methodSymbol())
                    .map(
                            tree ->
                                    string -> {
                                        if (matchContext.isHookContext()
                                                || matchContext.objectShouldMatchExactTypes()) {
                                            return tree.returnType().type().is(string);
                                        }
                                        return tree.returnType().type().is(string)
                                                || tree.returnType().type().isSubtypeOf(string);
                                    });
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public List<IType> getMethodParameterTypes(
            @Nonnull MatchContext matchContext, @Nonnull Tree methodInvocation) {
        Arguments arguments;
        if (methodInvocation instanceof MethodInvocationTree methodInvocationTree) {
            arguments = methodInvocationTree.arguments();
        } else if (methodInvocation instanceof NewClassTree newClassTree) {
            arguments = newClassTree.arguments();
        } else {
            return Collections.emptyList();
        }

        if (arguments.isEmpty()) {
            return Collections.emptyList();
        }

        final List<Boolean> parameterMatchExactTypes =
                matchContext.parametersShouldMatchExactTypes();
        List<Boolean> matchMatrix = parameterMatchExactTypes;
        if (parameterMatchExactTypes.size() != arguments.size()) {
            final Boolean[] defaults = new Boolean[arguments.size()];
            Arrays.fill(defaults, false);
            matchMatrix = Arrays.asList(defaults);
        }

        final List<IType> types = new ArrayList<>();
        for (int i = 0; i < arguments.size(); i++) {
            final ExpressionTree argument = arguments.get(i);
            final boolean exactMatch = matchMatrix.get(i);

            if (argument instanceof MethodInvocationTree methodInvocationTree) {
                Optional<IType> returnType =
                        getMethodReturnTypeString(
                                new MatchContext(
                                        matchContext.isHookContext(),
                                        exactMatch,
                                        Collections.emptyList()),
                                methodInvocationTree);
                if (returnType.isPresent()) {
                    types.add(returnType.get());
                    continue;
                }
            }

            types.add(
                    string -> {
                        if (exactMatch) {
                            return argument.symbolType().is(string);
                        }
                        return argument.symbolType().is(string)
                                || argument.symbolType().isSubtypeOf(string);
                    });
        }
        return types;
    }

    @Nonnull
    @Override
    public Optional<String> resolveIdentifierAsString(
            @Nonnull MatchContext matchContext, @Nonnull Tree identifier) {
        if (identifier instanceof IdentifierTree identifierTree) {
            return Optional.of(identifierTree.identifierToken().text());
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<String> getEnumIdentifierName(
            @Nonnull MatchContext matchContext, @Nonnull Tree enumIdentifier) {
        if (enumIdentifier instanceof IdentifierTree identifierTree) {
            return Optional.of(identifierTree.name());
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<String> getEnumClassName(
            @Nonnull MatchContext matchContext, @Nonnull Tree enumClass) {
        if (enumClass instanceof ClassTree classTree) {
            IdentifierTree enumClassIdentifier = classTree.simpleName();
            if (enumClassIdentifier == null) {
                return Optional.empty();
            }
            return Optional.of(enumClassIdentifier.name());
        }
        return Optional.empty();
    }
}
