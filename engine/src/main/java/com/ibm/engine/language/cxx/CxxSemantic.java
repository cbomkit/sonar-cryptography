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
package com.ibm.engine.language.cxx;

import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.model.factory.IValueFactory;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.GenericTokenType;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.cxx.parser.CxxGrammarImpl;
import org.sonar.cxx.parser.CxxTokenType;
import org.sonar.cxx.utils.CxxAstNodeHelper;
import org.sonar.cxx.utils.CxxConstantUtils;

public final class CxxSemantic {
    private static final Logger LOGGER = LoggerFactory.getLogger(CxxSemantic.class);

    private CxxSemantic() {
        // private
    }

    @Nonnull
    public static <O> List<ResolvedValue<O, AstNode>> resolveValues(
            @Nonnull Class<O> clazz,
            @Nonnull AstNode tree,
            @Nonnull LinkedList<AstNode> selections,
            @Nullable IValueFactory<AstNode> valueFactory,
            boolean returnEnclosingParam,
            @Nullable CxxDetectionEngine detectionEngine) {
        return resolveValuesInternal(
                clazz, tree, selections, valueFactory, returnEnclosingParam, detectionEngine, 0);
    }

    @Nonnull
    private static <O> List<ResolvedValue<O, AstNode>> resolveValuesInternal(
            @Nonnull Class<O> clazz,
            @Nonnull AstNode tree,
            @Nonnull LinkedList<AstNode> selections,
            @Nullable IValueFactory<AstNode> valueFactory,
            boolean returnEnclosingParam,
            @Nullable CxxDetectionEngine detectionEngine,
            int depth) {
        if (depth > 15) {
            return Collections.emptyList();
        }

        if (tree.is(CxxTokenType.STRING)) {
            return resolveStringLiteral(clazz, tree);
        } else if (tree.is(CxxTokenType.NUMBER)) {
            return resolveNumberLiteral(clazz, tree);
        } else if (tree.is(CxxTokenType.CHARACTER)) {
            return resolveCharLiteral(clazz, tree);
        } else if (tree.is(GenericTokenType.IDENTIFIER)) {
            return resolveIdentifier(
                    clazz,
                    tree,
                    selections,
                    valueFactory,
                    returnEnclosingParam,
                    detectionEngine,
                    depth);
        } else if (tree.is(CxxGrammarImpl.primaryExpression)) {
            return resolvePrimaryExpression(
                    clazz,
                    tree,
                    selections,
                    valueFactory,
                    returnEnclosingParam,
                    detectionEngine,
                    depth);
        } else if (tree.is(CxxGrammarImpl.LITERAL)) {
            return resolveLiteral(
                    clazz,
                    tree,
                    selections,
                    valueFactory,
                    returnEnclosingParam,
                    detectionEngine,
                    depth);
        } else if (tree.is(CxxGrammarImpl.assignmentExpression)) {
            return resolveAssignmentExpression(
                    clazz,
                    tree,
                    selections,
                    valueFactory,
                    returnEnclosingParam,
                    detectionEngine,
                    depth);
        } else if (tree.is(CxxGrammarImpl.initializerClause)) {
            return resolveInitializerClause(
                    clazz,
                    tree,
                    selections,
                    valueFactory,
                    returnEnclosingParam,
                    detectionEngine,
                    depth);
        } else if (tree.is(CxxGrammarImpl.expression)) {
            return resolveExpression(
                    clazz,
                    tree,
                    selections,
                    valueFactory,
                    returnEnclosingParam,
                    detectionEngine,
                    depth);
        } else if (CxxAstNodeHelper.isFunctionCall(tree)) {
            return resolveFunctionCall(clazz, tree, returnEnclosingParam, detectionEngine, depth);
        } else {
            AstNode firstChild = tree.getFirstChild();
            if (firstChild != null) {
                return resolveValuesInternal(
                        clazz,
                        firstChild,
                        selections,
                        valueFactory,
                        returnEnclosingParam,
                        detectionEngine,
                        depth + 1);
            }
        }

        return Collections.emptyList();
    }

    @Nonnull
    private static <O> List<ResolvedValue<O, AstNode>> resolveStringLiteral(
            @Nonnull Class<O> clazz, @Nonnull AstNode tree) {
        String value = tree.getTokenValue();
        if (value.startsWith("\"") && value.endsWith("\"") && value.length() >= 2) {
            value = value.substring(1, value.length() - 1);
        } else if (value.startsWith("L\"") && value.endsWith("\"") && value.length() >= 3) {
            value = value.substring(2, value.length() - 1);
        } else if (value.startsWith("u\"") && value.endsWith("\"") && value.length() >= 3) {
            value = value.substring(2, value.length() - 1);
        } else if (value.startsWith("U\"") && value.endsWith("\"") && value.length() >= 3) {
            value = value.substring(2, value.length() - 1);
        } else if (value.startsWith("u8\"") && value.endsWith("\"") && value.length() >= 4) {
            value = value.substring(3, value.length() - 1);
        } else if (value.startsWith("R\"") && value.endsWith("\"")) {
            int parenOpen = value.indexOf('(');
            int parenClose = value.lastIndexOf(')');
            if (parenOpen >= 0 && parenClose > parenOpen) {
                value = value.substring(parenOpen + 1, parenClose);
            }
        }
        Optional<O> result = castValue(clazz, value);
        return result.map(v -> List.of(new ResolvedValue<>(v, tree)))
                .orElse(Collections.emptyList());
    }

    @Nonnull
    private static <O> List<ResolvedValue<O, AstNode>> resolveNumberLiteral(
            @Nonnull Class<O> clazz, @Nonnull AstNode tree) {
        String value = tree.getTokenValue();
        value = value.replaceAll("[uUlLfF]", "");
        value = value.replace("'", "");

        Object result;
        try {
            if (value.startsWith("0x") || value.startsWith("0X")) {
                String digits = value.substring(2);
                // Use unsigned parsing to handle values > 0x7FFFFFFF (e.g. SSL_OP_* flags)
                result =
                        digits.length() <= 8
                                ? Integer.parseUnsignedInt(digits, 16)
                                : Long.parseUnsignedLong(digits, 16);
            } else if (value.startsWith("0b") || value.startsWith("0B")) {
                String digits = value.substring(2);
                result =
                        digits.length() <= 31
                                ? Integer.parseUnsignedInt(digits, 2)
                                : Long.parseUnsignedLong(digits, 2);
            } else if (value.startsWith("0") && value.length() > 1 && !value.contains(".")) {
                String digits = value.substring(1);
                result =
                        digits.length() <= 10
                                ? Integer.parseUnsignedInt(digits, 8)
                                : Long.parseUnsignedLong(digits, 8);
            } else if (value.contains(".") || value.contains("e") || value.contains("E")) {
                result = Double.parseDouble(value);
            } else {
                long v = Long.parseLong(value);
                result = (v >= Integer.MIN_VALUE && v <= Integer.MAX_VALUE) ? (int) v : v;
            }
        } catch (NumberFormatException e) {
            result = value;
        }
        Optional<O> castResult = castValue(clazz, result);
        return castResult
                .map(v -> List.of(new ResolvedValue<>(v, tree)))
                .orElse(Collections.emptyList());
    }

    @Nonnull
    private static <O> List<ResolvedValue<O, AstNode>> resolveCharLiteral(
            @Nonnull Class<O> clazz, @Nonnull AstNode tree) {
        String value = tree.getTokenValue();
        if (value.startsWith("'") && value.endsWith("'") && value.length() >= 3) {
            value = value.substring(1, value.length() - 1);
        }
        Optional<O> result = castValue(clazz, value);
        return result.map(v -> List.of(new ResolvedValue<>(v, tree)))
                .orElse(Collections.emptyList());
    }

    @Nonnull
    private static <O> List<ResolvedValue<O, AstNode>> resolveIdentifier(
            @Nonnull Class<O> clazz,
            @Nonnull AstNode tree,
            @Nonnull LinkedList<AstNode> selections,
            @Nullable IValueFactory<AstNode> valueFactory,
            boolean returnEnclosingParam,
            @Nullable CxxDetectionEngine detectionEngine,
            int depth) {
        String name = tree.getTokenValue();
        if ("true".equals(name)) {
            Optional<O> result = castValue(clazz, Boolean.TRUE);
            return result.map(v -> List.of(new ResolvedValue<>(v, tree)))
                    .orElse(Collections.emptyList());
        } else if ("false".equals(name)) {
            Optional<O> result = castValue(clazz, Boolean.FALSE);
            return result.map(v -> List.of(new ResolvedValue<>(v, tree)))
                    .orElse(Collections.emptyList());
        } else if ("nullptr".equals(name)) {
            Optional<O> result = castValue(clazz, "nullptr");
            return result.map(v -> List.of(new ResolvedValue<>(v, tree)))
                    .orElse(Collections.emptyList());
        }

        // Try to resolve as compile-time constant using CxxConstantUtils
        try {
            Object constantValue = CxxConstantUtils.resolveAsConstant(tree);
            if (constantValue != null) {
                LOGGER.debug("Resolved identifier '{}' to constant value: {}", name, constantValue);
                Optional<O> result = castValue(clazz, constantValue);
                if (result.isPresent()) {
                    return List.of(new ResolvedValue<>(result.get(), tree));
                }
            }
        } catch (Exception e) {
            // If constant resolution fails, fall back to identifier name
            LOGGER.debug("Could not resolve identifier '{}' as constant: {}", name, e.getMessage());
        }

        // Fallback to identifier name if not a constant
        if (returnEnclosingParam) {
            Optional<O> result = castValue(clazz, name);
            return result.map(v -> List.of(new ResolvedValue<>(v, tree)))
                    .orElse(Collections.emptyList());
        }

        Optional<O> result = castValue(clazz, name);
        return result.map(v -> List.of(new ResolvedValue<>(v, tree)))
                .orElse(Collections.emptyList());
    }

    @Nonnull
    private static <O> List<ResolvedValue<O, AstNode>> resolvePrimaryExpression(
            @Nonnull Class<O> clazz,
            @Nonnull AstNode tree,
            @Nonnull LinkedList<AstNode> selections,
            @Nullable IValueFactory<AstNode> valueFactory,
            boolean returnEnclosingParam,
            @Nullable CxxDetectionEngine detectionEngine,
            int depth) {
        AstNode literal = tree.getFirstChild(CxxGrammarImpl.LITERAL);
        if (literal != null) {
            return resolveLiteral(
                    clazz,
                    literal,
                    selections,
                    valueFactory,
                    returnEnclosingParam,
                    detectionEngine,
                    depth);
        }

        AstNode idExpression = tree.getFirstChild(CxxGrammarImpl.idExpression);
        if (idExpression != null) {
            String identifierName = CxxAstNodeHelper.getIdentifierName(idExpression);
            if (identifierName != null) {
                Optional<O> result = castValue(clazz, identifierName);
                return result.map(v -> List.of(new ResolvedValue<>(v, tree)))
                        .orElse(Collections.emptyList());
            }
        }

        AstNode firstChild = tree.getFirstChild();
        if (firstChild != null) {
            return resolveValuesInternal(
                    clazz,
                    firstChild,
                    selections,
                    valueFactory,
                    returnEnclosingParam,
                    detectionEngine,
                    depth + 1);
        }

        return Collections.emptyList();
    }

    @Nonnull
    private static <O> List<ResolvedValue<O, AstNode>> resolveLiteral(
            @Nonnull Class<O> clazz,
            @Nonnull AstNode tree,
            @Nonnull LinkedList<AstNode> selections,
            @Nullable IValueFactory<AstNode> valueFactory,
            boolean returnEnclosingParam,
            @Nullable CxxDetectionEngine detectionEngine,
            int depth) {
        AstNode stringLiteral = tree.getFirstChild(CxxTokenType.STRING);
        if (stringLiteral != null) {
            return resolveStringLiteral(clazz, stringLiteral);
        }

        AstNode numberLiteral = tree.getFirstChild(CxxTokenType.NUMBER);
        if (numberLiteral != null) {
            return resolveNumberLiteral(clazz, numberLiteral);
        }

        AstNode charLiteral = tree.getFirstChild(CxxTokenType.CHARACTER);
        if (charLiteral != null) {
            return resolveCharLiteral(clazz, charLiteral);
        }

        AstNode boolLiteral = tree.getFirstChild(CxxGrammarImpl.BOOL);
        if (boolLiteral != null) {
            String value = boolLiteral.getTokenValue();
            Boolean boolValue = "true".equals(value);
            Optional<O> result = castValue(clazz, boolValue);
            return result.map(v -> List.of(new ResolvedValue<>(v, tree)))
                    .orElse(Collections.emptyList());
        }

        AstNode nullptrLiteral = tree.getFirstChild(CxxGrammarImpl.NULLPTR);
        if (nullptrLiteral != null) {
            Optional<O> result = castValue(clazz, "nullptr");
            return result.map(v -> List.of(new ResolvedValue<>(v, tree)))
                    .orElse(Collections.emptyList());
        }

        AstNode firstChild = tree.getFirstChild();
        if (firstChild != null) {
            return resolveValuesInternal(
                    clazz,
                    firstChild,
                    selections,
                    valueFactory,
                    returnEnclosingParam,
                    detectionEngine,
                    depth + 1);
        }

        return Collections.emptyList();
    }

    @Nonnull
    private static <O> List<ResolvedValue<O, AstNode>> resolveAssignmentExpression(
            @Nonnull Class<O> clazz,
            @Nonnull AstNode tree,
            @Nonnull LinkedList<AstNode> selections,
            @Nullable IValueFactory<AstNode> valueFactory,
            boolean returnEnclosingParam,
            @Nullable CxxDetectionEngine detectionEngine,
            int depth) {
        List<AstNode> children = tree.getChildren();
        if (!children.isEmpty()) {
            AstNode lastChild = children.get(children.size() - 1);
            return resolveValuesInternal(
                    clazz,
                    lastChild,
                    selections,
                    valueFactory,
                    returnEnclosingParam,
                    detectionEngine,
                    depth + 1);
        }
        return Collections.emptyList();
    }

    @Nonnull
    private static <O> List<ResolvedValue<O, AstNode>> resolveInitializerClause(
            @Nonnull Class<O> clazz,
            @Nonnull AstNode tree,
            @Nonnull LinkedList<AstNode> selections,
            @Nullable IValueFactory<AstNode> valueFactory,
            boolean returnEnclosingParam,
            @Nullable CxxDetectionEngine detectionEngine,
            int depth) {
        AstNode assignmentExpression = tree.getFirstChild(CxxGrammarImpl.assignmentExpression);
        if (assignmentExpression != null) {
            return resolveAssignmentExpression(
                    clazz,
                    assignmentExpression,
                    selections,
                    valueFactory,
                    returnEnclosingParam,
                    detectionEngine,
                    depth);
        }
        AstNode firstChild = tree.getFirstChild();
        if (firstChild != null) {
            return resolveValuesInternal(
                    clazz,
                    firstChild,
                    selections,
                    valueFactory,
                    returnEnclosingParam,
                    detectionEngine,
                    depth + 1);
        }
        return Collections.emptyList();
    }

    @Nonnull
    private static <O> List<ResolvedValue<O, AstNode>> resolveExpression(
            @Nonnull Class<O> clazz,
            @Nonnull AstNode tree,
            @Nonnull LinkedList<AstNode> selections,
            @Nullable IValueFactory<AstNode> valueFactory,
            boolean returnEnclosingParam,
            @Nullable CxxDetectionEngine detectionEngine,
            int depth) {
        AstNode firstChild = tree.getFirstChild();
        if (firstChild != null) {
            return resolveValuesInternal(
                    clazz,
                    firstChild,
                    selections,
                    valueFactory,
                    returnEnclosingParam,
                    detectionEngine,
                    depth + 1);
        }
        return Collections.emptyList();
    }

    @Nonnull
    private static <O> List<ResolvedValue<O, AstNode>> resolveFunctionCall(
            @Nonnull Class<O> clazz,
            @Nonnull AstNode tree,
            boolean returnEnclosingParam,
            @Nullable CxxDetectionEngine detectionEngine,
            int depth) {
        String functionName = CxxAstNodeHelper.getFunctionCallName(tree);
        if (functionName != null) {
            Optional<O> result = castValue(clazz, functionName);
            return result.map(v -> List.of(new ResolvedValue<>(v, tree)))
                    .orElse(Collections.emptyList());
        }
        return Collections.emptyList();
    }

    @Nonnull
    private static <O> Optional<O> castValue(@Nonnull Class<O> clazz, @Nullable Object value) {
        if (value == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(clazz.cast(value));
        } catch (ClassCastException e) {
            if (clazz == String.class) {
                @SuppressWarnings("unchecked")
                O stringValue = (O) value.toString();
                return Optional.of(stringValue);
            }
            return Optional.empty();
        }
    }
}
