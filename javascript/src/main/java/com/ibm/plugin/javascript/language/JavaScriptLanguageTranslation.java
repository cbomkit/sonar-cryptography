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
package com.ibm.plugin.javascript.language;

import com.ibm.engine.detection.IType;
import com.ibm.engine.detection.MatchContext;
import com.ibm.engine.language.ILanguageTranslation;
import com.ibm.plugin.javascript.api.CallExpressionTree;
import com.ibm.plugin.javascript.api.CallExpressionWithBlockTree;
import com.ibm.plugin.javascript.api.IdentifierTree;
import com.ibm.plugin.javascript.api.LiteralTree;
import com.ibm.plugin.javascript.api.MemberExpressionTree;
import com.ibm.plugin.javascript.api.NewExpressionTree;
import com.ibm.plugin.javascript.api.Tree;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Language translation for JavaScript AST nodes produced by the ESLint bridge. */
public final class JavaScriptLanguageTranslation implements ILanguageTranslation<Tree> {

    @Nonnull
    private static final Logger LOGGER =
            LoggerFactory.getLogger(JavaScriptLanguageTranslation.class);

    @Nonnull
    @Override
    public Optional<String> getMethodName(
            @Nonnull MatchContext matchContext, @Nonnull Tree methodInvocation) {
        if (methodInvocation instanceof CallExpressionTree call) {
            return Optional.of(call.methodName());
        }
        if (methodInvocation instanceof CallExpressionWithBlockTree wrapped) {
            return Optional.of(wrapped.methodName());
        }
        if (methodInvocation instanceof NewExpressionTree newExpression) {
            return Optional.of("<init>");
        }
        if (methodInvocation instanceof MemberExpressionTree member) {
            return Optional.of(member.propertyName());
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<IType> getInvokedObjectTypeString(
            @Nonnull MatchContext matchContext, @Nonnull Tree methodInvocation) {
        Optional<String> typeName = resolveObjectType(methodInvocation);
        return typeName.map(name -> createJavaScriptType(name, matchContext));
    }

    @Nonnull
    @Override
    public Optional<IType> getMethodReturnTypeString(
            @Nonnull MatchContext matchContext, @Nonnull Tree methodInvocation) {
        if (methodInvocation instanceof CallExpressionTree call
                && call.resultType() != null
                && !call.resultType().isBlank()) {
            return Optional.of(createJavaScriptType(call.resultType(), matchContext));
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public List<IType> getMethodParameterTypes(
            @Nonnull MatchContext matchContext, @Nonnull Tree methodInvocation) {
        List<Tree> arguments = extractArguments(methodInvocation);
        if (arguments.isEmpty()) {
            return Collections.emptyList();
        }
        List<IType> types = new ArrayList<>();
        for (Tree argument : arguments) {
            types.add(createArgumentType(argument, matchContext));
        }
        return types;
    }

    @Nonnull
    @Override
    public Optional<String> resolveIdentifierAsString(
            @Nonnull MatchContext matchContext, @Nonnull Tree identifierTree) {
        if (identifierTree instanceof IdentifierTree identifier) {
            return Optional.of(identifier.name());
        }
        if (identifierTree instanceof LiteralTree literal) {
            return Optional.of(literal.value());
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<String> getEnumIdentifierName(
            @Nonnull MatchContext matchContext, @Nonnull Tree enumIdentifier) {
        return resolveIdentifierAsString(matchContext, enumIdentifier);
    }

    @Nonnull
    @Override
    public Optional<String> getEnumClassName(
            @Nonnull MatchContext matchContext, @Nonnull Tree enumClass) {
        return Optional.empty();
    }

    @Override
    public boolean supportsSubsetParameterMatching() {
        return true;
    }

    @Nonnull
    private Optional<String> resolveObjectType(@Nonnull Tree methodInvocation) {
        if (methodInvocation instanceof CallExpressionTree call) {
            return Optional.of(call.objectType());
        }
        if (methodInvocation instanceof CallExpressionWithBlockTree wrapped) {
            return Optional.of(wrapped.objectType());
        }
        if (methodInvocation instanceof NewExpressionTree newExpression) {
            return Optional.of(newExpression.objectType());
        }
        if (methodInvocation instanceof MemberExpressionTree member) {
            return Optional.of(member.objectType());
        }
        return Optional.empty();
    }

    @Nonnull
    private List<Tree> extractArguments(@Nonnull Tree methodInvocation) {
        if (methodInvocation instanceof CallExpressionTree call) {
            return call.arguments();
        }
        if (methodInvocation instanceof CallExpressionWithBlockTree wrapped) {
            return wrapped.arguments();
        }
        if (methodInvocation instanceof NewExpressionTree newExpression) {
            return newExpression.arguments();
        }
        return Collections.emptyList();
    }

    @Nonnull
    private IType createJavaScriptType(
            @Nonnull String typeName, @Nonnull MatchContext matchContext) {
        return expectedType -> matchesType(typeName, expectedType);
    }

    @Nonnull
    private IType createArgumentType(@Nonnull Tree argument, @Nonnull MatchContext matchContext) {
        String typeName = inferArgumentType(argument);
        return createJavaScriptType(typeName, matchContext);
    }

    @Nonnull
    private String inferArgumentType(@Nonnull Tree argument) {
        if (argument instanceof LiteralTree literal) {
            return literal.inferredType();
        }
        if (argument instanceof IdentifierTree identifier) {
            if (identifier.resolvedModule() != null) {
                return identifier.resolvedModule();
            }
            return "any";
        }
        if (argument instanceof CallExpressionTree call) {
            if (call.resultType() != null) {
                return call.resultType();
            }
            return call.objectType();
        }
        if (argument instanceof MemberExpressionTree member) {
            return member.objectType() + "." + member.propertyName();
        }
        return "any";
    }

    private boolean matchesType(@Nonnull String actual, @Nonnull String expected) {
        if (actual.equals(expected)) {
            return true;
        }
        if ("any".equals(expected)) {
            return true;
        }
        String normalizedActual = normalizeType(actual);
        String normalizedExpected = normalizeType(expected);
        if (normalizedActual.equals(normalizedExpected)) {
            return true;
        }
        if (normalizedExpected.endsWith(".*")
                && normalizedActual.startsWith(
                        normalizedExpected.substring(0, normalizedExpected.length() - 1))) {
            return true;
        }
        if (expected.endsWith(".*")
                && actual.startsWith(expected.substring(0, expected.length() - 1))) {
            return true;
        }
        return false;
    }

    @Nonnull
    private String normalizeType(@Nonnull String typeName) {
        return typeName.trim();
    }
}
