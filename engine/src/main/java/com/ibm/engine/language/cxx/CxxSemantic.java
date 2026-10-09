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
import com.sonar.cxx.sslr.api.AstNodeType;
import com.sonar.cxx.sslr.api.GenericTokenType;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.cxx.parser.CxxGrammarImpl;
import org.sonar.cxx.parser.CxxKeyword;
import org.sonar.cxx.parser.CxxPunctuator;
import org.sonar.cxx.parser.CxxTokenType;
import org.sonar.cxx.squidbridge.api.AstNodeSymbolExtension;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.api.SymbolTable;
import org.sonar.cxx.utils.CxxAstNodeHelper;
import org.sonar.cxx.utils.CxxConstantUtils;

public final class CxxSemantic {
    private static final Logger LOGGER = LoggerFactory.getLogger(CxxSemantic.class);

    /**
     * Constant-style name: an uppercase prefix followed by at least one underscore-separated part,
     * e.g. {@code TLS1_2_VERSION}, {@code NID_sha256} or {@code OSSL_KDF_NAME_HKDF}.
     */
    private static final Pattern MACRO_NAME = Pattern.compile("[A-Z][A-Z0-9]*(_[A-Za-z0-9]+)+");

    /** A name a function can have. */
    private static final Pattern FUNCTION_NAME = Pattern.compile("[A-Za-z_][A-Za-z0-9_]*");

    /** Arithmetic, shift, bitwise and unary operator expressions. */
    private static final AstNodeType[] OPERATOR_EXPRESSIONS = {
        CxxGrammarImpl.multiplicativeExpression,
        CxxGrammarImpl.additiveExpression,
        CxxGrammarImpl.shiftExpression,
        CxxGrammarImpl.andExpression,
        CxxGrammarImpl.exclusiveOrExpression,
        CxxGrammarImpl.inclusiveOrExpression,
        CxxGrammarImpl.unaryExpression
    };

    /** The C++ cast keywords, e.g. {@code static_cast} in {@code static_cast<int>(x)}. */
    private static final AstNodeType[] NAMED_CASTS = {
        CxxKeyword.STATIC_CAST,
        CxxKeyword.REINTERPRET_CAST,
        CxxKeyword.CONST_CAST,
        CxxKeyword.DYNAMIC_CAST
    };

    private static final Pattern INTEGER_SUFFIX_PATTERN = Pattern.compile("[uUlL]+$");
    private static final Pattern FLOAT_SUFFIX_PATTERN = Pattern.compile("[fFlL]+$");

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
                clazz,
                tree,
                selections,
                valueFactory,
                returnEnclosingParam,
                detectionEngine,
                0,
                new Resolution());
    }

    @Nonnull
    private static <O> List<ResolvedValue<O, AstNode>> resolveValuesInternal(
            @Nonnull Class<O> clazz,
            @Nonnull AstNode tree,
            @Nonnull LinkedList<AstNode> selections,
            @Nullable IValueFactory<AstNode> valueFactory,
            boolean returnEnclosingParam,
            @Nullable CxxDetectionEngine detectionEngine,
            int depth,
            @Nonnull Resolution resolution) {
        if (depth > 15) {
            resolution.cutOffs++;
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
                    depth,
                    resolution);
        } else if (tree.is(CxxGrammarImpl.primaryExpression)) {
            return resolvePrimaryExpression(
                    clazz,
                    tree,
                    selections,
                    valueFactory,
                    returnEnclosingParam,
                    detectionEngine,
                    depth,
                    resolution);
        } else if (tree.is(CxxGrammarImpl.BOOL)) {
            return castValue(clazz, "true".equals(tree.getTokenValue()))
                    .map(value -> List.of(new ResolvedValue<>(value, tree)))
                    .orElse(Collections.emptyList());
        } else if (tree.is(CxxGrammarImpl.LITERAL)) {
            return resolveLiteral(
                    clazz,
                    tree,
                    selections,
                    valueFactory,
                    returnEnclosingParam,
                    detectionEngine,
                    depth,
                    resolution);
        } else if (tree.is(CxxGrammarImpl.assignmentExpression)) {
            return resolveAssignmentExpression(
                    clazz,
                    tree,
                    selections,
                    valueFactory,
                    returnEnclosingParam,
                    detectionEngine,
                    depth,
                    resolution);
        } else if (tree.is(CxxGrammarImpl.initializerClause)) {
            return resolveInitializerClause(
                    clazz,
                    tree,
                    selections,
                    valueFactory,
                    returnEnclosingParam,
                    detectionEngine,
                    depth,
                    resolution);
        } else if (tree.is(CxxGrammarImpl.expression)) {
            return resolveExpression(
                    clazz,
                    tree,
                    selections,
                    valueFactory,
                    returnEnclosingParam,
                    detectionEngine,
                    depth,
                    resolution);
        } else if (tree.is(CxxGrammarImpl.bracedInitList)) {
            return resolveBracedInitList(clazz, tree);
        } else if (tree.is(CxxGrammarImpl.qualifiedId)) {
            // idExpression is .skip()-annotated, so a qualified reference (Type::CONSTANT)
            // surfaces its qualifiedId node directly, with no dedicated wrapper. The referenced
            // identifier is qualifiedId's last child (unqualifiedId collapses to a bare
            // IDENTIFIER when it has only one child), not its first child (the LHS type name).
            AstNode referencedId = tree.getLastChild();
            if (referencedId != null) {
                return resolveValuesInternal(
                        clazz,
                        referencedId,
                        selections,
                        valueFactory,
                        returnEnclosingParam,
                        detectionEngine,
                        depth + 1,
                        resolution);
            }
        } else if (tree.is(CxxGrammarImpl.postfixExpression)
                && tree.getFirstChild().is(NAMED_CASTS)) {
            // "static_cast<type>(operand)" and the other C++ casts: the value of the operand
            final AstNode open = tree.getFirstChild(CxxPunctuator.BR_LEFT);
            final AstNode operand = open != null ? open.getNextSibling() : null;
            if (operand != null) {
                return resolveValuesInternal(
                        clazz,
                        operand,
                        selections,
                        valueFactory,
                        returnEnclosingParam,
                        detectionEngine,
                        depth + 1,
                        resolution);
            }
        } else if (isArrayElement(tree)) {
            return resolveArrayElement(
                    clazz,
                    tree.getFirstChild(),
                    indicesOf(tree.getChildren()),
                    tree,
                    selections,
                    valueFactory,
                    returnEnclosingParam,
                    detectionEngine,
                    depth,
                    resolution);
        } else if (CxxAstNodeHelper.isFunctionCall(tree)) {
            return resolveFunctionCall(clazz, tree, returnEnclosingParam, detectionEngine, depth);
        } else if (tree.is(CxxGrammarImpl.conditionalExpression)) {
            return resolveConditionalExpression(
                    clazz,
                    tree,
                    selections,
                    valueFactory,
                    returnEnclosingParam,
                    detectionEngine,
                    depth,
                    resolution);
        } else if (tree.is(CxxGrammarImpl.castExpression)) {
            // "(type) operand": the value of the operand
            return resolveValuesInternal(
                    clazz,
                    tree.getLastChild(),
                    selections,
                    valueFactory,
                    returnEnclosingParam,
                    detectionEngine,
                    depth + 1,
                    resolution);
        } else if (isAddressOfAFunction(tree)) {
            // "&f" designates the function f, as "f" does
            return resolveValuesInternal(
                    clazz,
                    tree.getLastChild(),
                    selections,
                    valueFactory,
                    returnEnclosingParam,
                    detectionEngine,
                    depth + 1,
                    resolution);
        } else if (tree.is(OPERATOR_EXPRESSIONS)) {
            // an operator expression has a value only when it is a compile-time constant, or when
            // it combines flags named by macros of a header that is not part of the analyzed code,
            // e.g. SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1, whose value is the flags it combines, as a
            // macro's name is its value
            final Object constant = CxxConstantUtils.resolveAsConstant(tree);
            return castValue(clazz, constant != null ? constant : combinedFlags(tree))
                    .map(value -> List.of(new ResolvedValue<>(value, tree)))
                    .orElse(Collections.emptyList());
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
                        depth + 1,
                        resolution);
            }
        }

        return Collections.emptyList();
    }

    /**
     * Whether an expression takes the address of a function, {@code &f}: of a function of the
     * analyzed code or of an undeclared name written in constant style, as a library function such
     * as {@code EVP_sha256} is, rather than of a variable.
     */
    private static boolean isAddressOfAFunction(@Nonnull AstNode tree) {
        if (!tree.is(CxxGrammarImpl.unaryExpression)
                || tree.getNumberOfChildren() != 2
                || !"&".equals(tree.getFirstChild().getTokenValue())
                || !tree.getLastChild().is(GenericTokenType.IDENTIFIER)) {
            return false;
        }
        final Symbol symbol = AstNodeSymbolExtension.getSymbol(tree.getLastChild());
        return symbol == null
                ? MACRO_NAME.matcher(tree.getLastChild().getTokenValue()).matches()
                : symbol instanceof Symbol.FunctionSymbol;
    }

    /**
     * The names of the functions a call through a function pointer calls: the functions the pointer
     * is assigned, by name or by address, for a call of a pointer variable ({@code get()} or {@code
     * (*get)()}) or of an element of an array of pointers ({@code getters[i]()}). Empty for a call
     * that is not made through a pointer of the analyzed code.
     */
    @Nonnull
    public static List<String> resolveCalledFunctions(@Nonnull AstNode call) {
        if (!CxxAstNodeHelper.isFunctionCall(call)) {
            return List.of();
        }
        final List<AstNode> children = call.getChildren();
        int open = children.size() - 1;
        while (open >= 0 && !children.get(open).is(CxxPunctuator.BR_LEFT)) {
            open--;
        }
        if (open < 1) {
            return List.of();
        }
        List<AstNode> callee = children.subList(0, open);
        // (*get)() and (*getters[i])() call the function the pointer points to
        if (callee.size() == 1
                && callee.get(0).is(CxxGrammarImpl.primaryExpression)
                && callee.get(0).getNumberOfChildren() == 3) {
            AstNode dereference = callee.get(0).getChildren().get(1);
            if (dereference.is(CxxGrammarImpl.expression)
                    && dereference.getNumberOfChildren() == 1) {
                dereference = dereference.getFirstChild();
            }
            if (dereference.is(CxxGrammarImpl.unaryExpression)
                    && dereference.getNumberOfChildren() == 2
                    && "*".equals(dereference.getFirstChild().getTokenValue())) {
                final AstNode pointer = dereference.getLastChild();
                callee =
                        pointer.is(CxxGrammarImpl.postfixExpression)
                                ? pointer.getChildren()
                                : List.of(pointer);
            }
        }
        // a name alone may be read as a type name, as in "get()"
        final AstNode first = callee.get(0);
        final AstNode name =
                first.getToken() == first.getLastToken() && !first.is(GenericTokenType.IDENTIFIER)
                        ? first.getFirstDescendant(GenericTokenType.IDENTIFIER)
                        : first;
        if (name == null
                || !name.is(GenericTokenType.IDENTIFIER)
                || !(AstNodeSymbolExtension.getSymbol(name) instanceof Symbol.VariableSymbol)) {
            return List.of();
        }
        final List<ResolvedValue<Object, AstNode>> values;
        if (callee.size() == 1) {
            values =
                    resolveValuesInternal(
                            Object.class,
                            name,
                            new LinkedList<>(),
                            null,
                            false,
                            null,
                            0,
                            new Resolution());
        } else if (isArrayElement(callee)) {
            values =
                    resolveArrayElement(
                            Object.class,
                            name,
                            indicesOf(callee),
                            call,
                            new LinkedList<>(),
                            null,
                            false,
                            null,
                            0,
                            new Resolution());
        } else {
            return List.of();
        }
        return values.stream()
                .map(ResolvedValue::value)
                .filter(String.class::isInstance)
                .map(String.class::cast)
                .filter(function -> FUNCTION_NAME.matcher(function).matches())
                .distinct()
                .toList();
    }

    /**
     * Whether a postfix expression is an element of an array variable, a name followed by
     * subscripts only: {@code names[i]} or {@code names[i][1]}.
     */
    private static boolean isArrayElement(@Nonnull AstNode tree) {
        return tree.is(CxxGrammarImpl.postfixExpression) && isArrayElement(tree.getChildren());
    }

    /** Whether nodes are a name followed by subscripts only, see {@link #isArrayElement}. */
    private static boolean isArrayElement(@Nonnull List<AstNode> children) {
        if (children.size() < 4
                || (children.size() - 1) % 3 != 0
                || !children.get(0).is(GenericTokenType.IDENTIFIER)) {
            return false;
        }
        for (int i = 1; i < children.size(); i += 3) {
            if (!children.get(i).is(CxxPunctuator.SQBR_LEFT)
                    || !children.get(i + 2).is(CxxPunctuator.SQBR_RIGHT)) {
                return false;
            }
        }
        return true;
    }

    /** The index expressions of an {@link #isArrayElement array element}, in order. */
    @Nonnull
    private static List<AstNode> indicesOf(@Nonnull List<AstNode> children) {
        final List<AstNode> indices = new ArrayList<>();
        for (int i = 2; i < children.size(); i += 3) {
            indices.add(children.get(i));
        }
        return indices;
    }

    /** The value of a constant index, or null when the index is not a compile-time constant. */
    @Nullable private static Long constantIndex(@Nonnull AstNode index) {
        AstNode expression = index;
        while (expression.is(CxxGrammarImpl.expressionList, CxxGrammarImpl.initializerList)
                && expression.getNumberOfChildren() == 1) {
            expression = expression.getFirstChild();
        }
        return CxxConstantUtils.resolveAsConstant(expression) instanceof Number number
                ? number.longValue()
                : null;
    }

    /**
     * Resolves an element of an array variable to the elements of the array's initializer and the
     * values assigned to its elements: at a constant index, the element at that index, counting a
     * designated element ({@code [2] = "SM3"}) at its index; at an index that is not constant,
     * every element. An element assigned with a constant index ({@code names[1] = v}) gives its
     * value to the elements at that index, one assigned with an index that is not constant to every
     * element. The array is guarded against cycles as a variable is.
     */
    @Nonnull
    private static <O> List<ResolvedValue<O, AstNode>> resolveArrayElement(
            @Nonnull Class<O> clazz,
            @Nonnull AstNode arrayName,
            @Nonnull List<AstNode> indices,
            @Nonnull AstNode element,
            @Nonnull LinkedList<AstNode> selections,
            @Nullable IValueFactory<AstNode> valueFactory,
            boolean returnEnclosingParam,
            @Nullable CxxDetectionEngine detectionEngine,
            int depth,
            @Nonnull Resolution resolution) {
        if (!(AstNodeSymbolExtension.getSymbol(arrayName) instanceof Symbol.VariableSymbol array)) {
            return Collections.emptyList();
        }
        if (!resolution.inProgress.add(array)) {
            resolution.cutOffs++;
            return Collections.emptyList();
        }
        try {
            final List<AstNode> values = new ArrayList<>();
            final AstNode initializer = array.initializer();
            final AstNode list = initializer == null ? null : initializer.getLastChild();
            if (list != null && list.is(CxxGrammarImpl.bracedInitList)) {
                List<AstNode> level = List.of(list);
                for (int i = 0; i < indices.size(); i++) {
                    final Long index = constantIndex(indices.get(i));
                    final List<AstNode> next = new ArrayList<>();
                    for (AstNode levelList : level) {
                        for (AstNode value : elementsAt(levelList, index)) {
                            if (i == indices.size() - 1) {
                                next.add(value);
                            } else if (value.is(CxxGrammarImpl.bracedInitList)) {
                                next.add(value);
                            }
                        }
                    }
                    level = next;
                }
                values.addAll(level);
            }
            for (Symbol.Usage usage : array.usages()) {
                final AstNode assignedElement = usage.node().getParent();
                if (assignedElement == null
                        || assignedElement == element
                        || assignedElement.getFirstChild() != usage.node()
                        || !isArrayElement(assignedElement)) {
                    continue;
                }
                final AstNode assignment = assignedElement.getParent();
                if (assignment == null
                        || !assignment.is(CxxGrammarImpl.assignmentExpression)
                        || assignment.getFirstChild() != assignedElement
                        || !"=".equals(assignment.getChildren().get(1).getTokenValue())
                        || !sameElement(indicesOf(assignedElement.getChildren()), indices)) {
                    continue;
                }
                values.add(assignment.getLastChild());
            }
            final List<ResolvedValue<O, AstNode>> result = new LinkedList<>();
            for (AstNode value : values) {
                result.addAll(
                        resolveValuesInternal(
                                clazz,
                                value,
                                selections,
                                valueFactory,
                                returnEnclosingParam,
                                detectionEngine,
                                depth + 1,
                                resolution));
            }
            return List.copyOf(new LinkedHashSet<>(result));
        } finally {
            resolution.inProgress.remove(array);
        }
    }

    /**
     * Whether an element assigned with the given indices may be the element read with the other
     * indices: of the same number of indices, each pair is equal or not constant.
     */
    private static boolean sameElement(
            @Nonnull List<AstNode> assigned, @Nonnull List<AstNode> read) {
        if (assigned.size() != read.size()) {
            return false;
        }
        for (int i = 0; i < assigned.size(); i++) {
            final Long assignedIndex = constantIndex(assigned.get(i));
            final Long readIndex = constantIndex(read.get(i));
            if (assignedIndex != null && readIndex != null && !assignedIndex.equals(readIndex)) {
                return false;
            }
        }
        return true;
    }

    /**
     * The values of the elements of a brace-enclosed initializer list at an index, or of every
     * element for a null index. A designated element, {@code [2] = "SM3"}, is at the index it
     * names, and the elements after it follow from there.
     */
    @Nonnull
    private static List<AstNode> elementsAt(@Nonnull AstNode list, @Nullable Long index) {
        final List<AstNode> values = new ArrayList<>();
        long position = 0;
        for (AstNode element : elementsOf(list)) {
            AstNode value = element;
            if (element.is(CxxGrammarImpl.designatedInitializerClause)) {
                final AstNode designator = element.getFirstChild(CxxGrammarImpl.designator);
                final AstNode at =
                        designator == null
                                ? null
                                : designator.getFirstChild(CxxGrammarImpl.constantExpression);
                if (at != null && CxxConstantUtils.resolveAsConstant(at) instanceof Number number) {
                    position = number.longValue();
                }
                value = element.getLastChild();
            }
            if (index == null || index == position) {
                values.add(value);
            }
            position++;
        }
        return values;
    }

    /**
     * The elements of a brace-enclosed initializer list, without the braces and commas: the
     * initializer clauses, or the designated initializer clauses of a designated list.
     */
    @Nonnull
    static List<AstNode> elementsOf(@Nonnull AstNode bracedInitList) {
        final List<AstNode> elements = new ArrayList<>();
        for (AstNode child : bracedInitList.getChildren()) {
            if (child.is(
                    CxxGrammarImpl.initializerList, CxxGrammarImpl.designatedInitializerList)) {
                child.getChildren().stream()
                        .filter(element -> !element.is(CxxPunctuator.COMMA))
                        .forEach(elements::add);
            } else if (!child.is(
                    CxxPunctuator.CURLBR_LEFT, CxxPunctuator.CURLBR_RIGHT, CxxPunctuator.COMMA)) {
                elements.add(child);
            }
        }
        return elements;
    }

    /**
     * The flags a bitwise or of macro names combines, written {@code
     * SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1} in the order they are written, or null when an operand is
     * not the name of a macro that is not declared in the analyzed code.
     */
    @Nullable private static String combinedFlags(@Nonnull AstNode tree) {
        final List<String> flags = new ArrayList<>();
        return collectFlags(tree, flags) && flags.size() > 1 ? String.join("|", flags) : null;
    }

    private static boolean collectFlags(@Nonnull AstNode operand, @Nonnull List<String> flags) {
        if (operand.is(CxxGrammarImpl.inclusiveOrExpression)) {
            for (AstNode child : operand.getChildren()) {
                if (!child.is(CxxPunctuator.BW_OR) && !collectFlags(child, flags)) {
                    return false;
                }
            }
            return true;
        }
        if (operand.is(CxxGrammarImpl.primaryExpression)
                && operand.getNumberOfChildren() == 3
                && operand.getFirstChild().is(CxxPunctuator.BR_LEFT)) {
            return collectFlags(operand.getChildren().get(1), flags);
        }
        if (operand.is(CxxGrammarImpl.expression) && operand.getNumberOfChildren() == 1) {
            return collectFlags(operand.getFirstChild(), flags);
        }
        if (operand.is(GenericTokenType.IDENTIFIER)
                && AstNodeSymbolExtension.getSymbol(operand) == null
                && MACRO_NAME.matcher(operand.getTokenValue()).matches()) {
            flags.add(operand.getTokenValue());
            return true;
        }
        return false;
    }

    /** True for the member name of a member access, e.g. {@code field} in {@code s.field}. */
    private static boolean isMemberAccessName(@Nonnull AstNode identifier) {
        AstNode previous = identifier.getPreviousSibling();
        return previous != null
                && (".".equals(previous.getTokenValue()) || "->".equals(previous.getTokenValue()));
    }

    /**
     * Resolves {@code condition ? whenTrue : whenFalse} to the selected branch when the condition
     * is a compile-time constant, and to the values of both branches otherwise.
     */
    @Nonnull
    private static <O> List<ResolvedValue<O, AstNode>> resolveConditionalExpression(
            @Nonnull Class<O> clazz,
            @Nonnull AstNode tree,
            @Nonnull LinkedList<AstNode> selections,
            @Nullable IValueFactory<AstNode> valueFactory,
            boolean returnEnclosingParam,
            @Nullable CxxDetectionEngine detectionEngine,
            int depth,
            @Nonnull Resolution resolution) {
        List<AstNode> children = tree.getChildren();
        if (children.size() != 5) {
            return Collections.emptyList();
        }
        List<AstNode> branches;
        Object condition = CxxConstantUtils.resolveAsConstant(children.get(0));
        if (condition instanceof Boolean bool) {
            branches = List.of(bool ? children.get(2) : children.get(4));
        } else if (condition instanceof Number number) {
            branches = List.of(number.longValue() != 0 ? children.get(2) : children.get(4));
        } else {
            branches = List.of(children.get(2), children.get(4));
        }
        List<ResolvedValue<O, AstNode>> result = new LinkedList<>();
        for (AstNode branch : branches) {
            result.addAll(
                    resolveValuesInternal(
                            clazz,
                            branch,
                            selections,
                            valueFactory,
                            returnEnclosingParam,
                            detectionEngine,
                            depth + 1,
                            resolution));
        }
        return result;
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
        if ("nullptr".equals(value)) {
            // the lexer reads the null pointer literal as a number
            return castValue(clazz, "nullptr")
                    .map(v -> List.of(new ResolvedValue<>(v, tree)))
                    .orElse(Collections.emptyList());
        }
        value = value.replace("'", "");
        boolean isHex = value.startsWith("0x") || value.startsWith("0X");
        // Hex literals never carry an f/F suffix (f/F there are hex digits), so only strip the
        // u/U/l/L integer suffix; non-hex literals may also carry a float f/F suffix.
        value =
                isHex
                        ? INTEGER_SUFFIX_PATTERN.matcher(value).replaceAll("")
                        : FLOAT_SUFFIX_PATTERN
                                .matcher(INTEGER_SUFFIX_PATTERN.matcher(value).replaceAll(""))
                                .replaceAll("");

        Object result;
        try {
            // an integer literal is an int when its value fits, a long otherwise, e.g. 0x80000000
            if (isHex) {
                result = integerValue(Long.parseUnsignedLong(value.substring(2), 16));
            } else if (value.startsWith("0b") || value.startsWith("0B")) {
                result = integerValue(Long.parseUnsignedLong(value.substring(2), 2));
            } else if (value.contains(".") || value.contains("e") || value.contains("E")) {
                result = Double.parseDouble(value);
            } else if (value.startsWith("0") && value.length() > 1) {
                result = integerValue(Long.parseUnsignedLong(value.substring(1), 8));
            } else {
                result = integerValue(Long.parseLong(value));
            }
        } catch (NumberFormatException e) {
            // a literal out of the range of the integer types, or not a valid number (e.g. the
            // octal 0999), has no value the compiler would accept
            return Collections.emptyList();
        }
        Optional<O> castResult = castValue(clazz, result);
        return castResult
                .map(v -> List.of(new ResolvedValue<>(v, tree)))
                .orElse(Collections.emptyList());
    }

    /** The value of an integer literal: an {@code int} when it fits, a {@code long} otherwise. */
    @Nonnull
    private static Object integerValue(long value) {
        return value >= Integer.MIN_VALUE && value <= Integer.MAX_VALUE
                ? (Object) (int) value
                : value;
    }

    /**
     * A brace-enclosed initializer list, e.g. an {@code OSSL_HPKE_SUITE} given as {@code
     * {OSSL_HPKE_KEM_ID_P256, OSSL_HPKE_KDF_ID_HKDF_SHA256, OSSL_HPKE_AEAD_ID_AES_GCM_256}}, has no
     * single scalar value: its value is the list of the source texts of its elements, which a value
     * factory that understands the structure it initializes reads. The value holds no syntax tree,
     * so that a call given such an argument can be kept without its file's tree.
     */
    @Nonnull
    private static <O> List<ResolvedValue<O, AstNode>> resolveBracedInitList(
            @Nonnull Class<O> clazz, @Nonnull AstNode tree) {
        final List<String> elements =
                elementsOf(tree).stream().map(CxxConstructorCalls::textOf).toList();
        return castValue(clazz, elements)
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
            int depth,
            @Nonnull Resolution resolution) {
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
            LOGGER.debug("Could not resolve identifier '{}' as constant: {}", name, e.getMessage());
        }

        // A field's or parameter's own name is never a resolved value. Parameters are still
        // returned when returnEnclosingParam is set, since that caller needs the node to hook the
        // enclosing function; a field has nothing to hook. A scoped enum's constants live only in
        // its qualified-only member scope (see Symbol.TypeSymbol#memberScope) and are never
        // registered in an enclosing scope, so the cheap direct lookup below always misses for
        // them; the qualified-reference (Mode::STRICT) fallback only runs on that miss, sparing the
        // unbounded ancestor walk it does for the overwhelmingly common non-scoped-enum identifier.
        Symbol symbol = AstNodeSymbolExtension.getSymbol(tree);
        if (symbol == null) {
            symbol = resolveScopedEnumConstant(tree);
        }
        if (symbol instanceof Symbol.VariableSymbol variableSymbol && !symbol.isUnknown()) {
            boolean skipField = variableSymbol.isField();
            boolean skipParameter = variableSymbol.isParameter() && !returnEnclosingParam;
            if (skipField || skipParameter) {
                return Collections.emptyList();
            }

            List<ResolvedValue<O, AstNode>> chased =
                    chaseVariableValues(
                            clazz,
                            tree,
                            variableSymbol,
                            selections,
                            valueFactory,
                            returnEnclosingParam,
                            detectionEngine,
                            depth,
                            resolution);
            if (!chased.isEmpty()) {
                return chased;
            }
            // A bare parameter with no local reassignment/initializer has nothing to chase, so
            // fall back to the parameter node itself, per the returnEnclosingParam contract above.
            if (variableSymbol.isParameter() && returnEnclosingParam) {
                Optional<O> result = castValue(clazz, name);
                if (result.isPresent()) {
                    return List.of(new ResolvedValue<>(result.get(), tree));
                }
            }
        } else if (symbol != null
                && symbol.kind() == Symbol.Kind.ENUM_CONSTANT
                && !symbol.isUnknown()) {
            List<ResolvedValue<O, AstNode>> resolved = resolveEnumConstant(clazz, symbol);
            if (!resolved.isEmpty()) {
                return resolved;
            }
        }

        // the name of a function used as a value designates the function, e.g. the function a
        // function pointer is assigned
        if (symbol instanceof Symbol.FunctionSymbol && !symbol.isUnknown()) {
            return castValue(clazz, name)
                    .map(value -> List.of(new ResolvedValue<>(value, tree)))
                    .orElse(Collections.emptyList());
        }

        // An undeclared name written in constant style (e.g. TLS1_2_VERSION, NID_sha256) is a macro
        // or constant defined in a header that is not part of the analyzed code; its name is its
        // value, which library rules map to what it stands for, as for an unresolved Python name.
        if (symbol == null && !isMemberAccessName(tree) && MACRO_NAME.matcher(name).matches()) {
            return castValue(clazz, name)
                    .map(value -> List.of(new ResolvedValue<>(value, tree)))
                    .orElse(Collections.emptyList());
        }

        // Any other identifier with no attached symbol (something declared in another translation
        // unit) is not itself a resolved value; resolution of such names is deferred to the
        // separate outer-scope resolution mechanism.
        return Collections.emptyList();
    }

    /**
     * Resolves a variable to its declaration-time initializer value and every subsequent
     * reassignment's value, matching how the Java engine chases {@code VariableTree.initializer()}
     * and assignment-site usages. The initializer's result (if any) comes first, followed by
     * reassignments in source order; an empty list means neither yielded a resolved value. A value
     * reached through several assignments is listed once.
     *
     * <p>The assignment graph can contain cycles (e.g. {@code a = b;} together with {@code b =
     * a;}): a variable that is already being resolved further up the call chain is not followed
     * again, since it cannot contribute a new value and following it would recurse forever,
     * matching the guard the Java engine carries for the same reason (issue #525).
     *
     * <p>A variable reached again through another assignment of the same resolution, e.g. {@code
     * v1} in {@code v2 = v1; if (c) v2 = v1;}, takes the values it was resolved to the first time,
     * so that a chain of such variables is resolved once per variable rather than once per path.
     * Only complete values are reused: values from which the depth limit or the cycle guard left
     * something out depend on where the variable was reached from.
     */
    @Nonnull
    private static <O> List<ResolvedValue<O, AstNode>> chaseVariableValues(
            @Nonnull Class<O> clazz,
            @Nonnull AstNode currentOccurrence,
            @Nonnull Symbol.VariableSymbol variableSymbol,
            @Nonnull LinkedList<AstNode> selections,
            @Nullable IValueFactory<AstNode> valueFactory,
            boolean returnEnclosingParam,
            @Nullable CxxDetectionEngine detectionEngine,
            int depth,
            @Nonnull Resolution resolution) {
        // the values of a variable do not include the assignment being resolved, so they can only
        // be reused when the occurrence is not one of the variable's own assignments
        final boolean reusable = !isWrittenAt(variableSymbol, currentOccurrence);
        if (reusable) {
            final List<ResolvedValue<O, AstNode>> known = resolution.valuesOf(variableSymbol);
            if (known != null) {
                return known;
            }
        }
        if (!resolution.inProgress.add(variableSymbol)) {
            // cycle: this variable is already being resolved further up the call chain
            resolution.cutOffs++;
            return Collections.emptyList();
        }
        final int cutOffsBefore = resolution.cutOffs;
        try {
            LinkedList<ResolvedValue<O, AstNode>> result = new LinkedList<>();

            for (Symbol.Usage usage : variableSymbol.usages()) {
                if (usage.node() == currentOccurrence) {
                    continue;
                }
                // a compound assignment (x += 16) combines the variable's value with another one,
                // so only a plain assignment of the variable itself gives it a value, as for Java's
                // Tree.Kind.ASSIGNMENT
                if (usage.kind() != Symbol.Usage.UsageKind.WRITE) {
                    continue;
                }
                AstNode assignmentExpr =
                        usage.node().getFirstAncestor(CxxGrammarImpl.assignmentExpression);
                if (assignmentExpr == null) {
                    continue;
                }
                AstNode assignedValue = assignmentExpr.getLastChild();
                if (assignedValue == null || assignedValue == usage.node()) {
                    continue;
                }
                result.addAll(
                        resolveValuesInternal(
                                clazz,
                                assignedValue,
                                selections,
                                valueFactory,
                                returnEnclosingParam,
                                detectionEngine,
                                depth + 1,
                                resolution));
            }

            AstNode initializer = variableSymbol.initializer();
            if (initializer != null) {
                // braceOrEqualInitializer is declared with .skip() and initializerClause with
                // .skipIfOneChild(), so for a plain "= <value>" declarator neither node survives in
                // the tree: initializer ends up with the "=" token as its first child and the
                // (possibly further-collapsed) value expression as its last child. Taking the
                // structurally last child, as with assignmentExpression above, reaches the value
                // regardless of how far it collapsed.
                AstNode initializerTarget = initializer.getLastChild();
                if (initializerTarget == null) {
                    initializerTarget = initializer;
                }
                List<ResolvedValue<O, AstNode>> initializerResults =
                        resolveValuesInternal(
                                clazz,
                                initializerTarget,
                                selections,
                                valueFactory,
                                returnEnclosingParam,
                                detectionEngine,
                                depth + 1,
                                resolution);
                result.addAll(0, initializerResults);
            }

            final List<ResolvedValue<O, AstNode>> values = List.copyOf(new LinkedHashSet<>(result));
            if (reusable && resolution.cutOffs == cutOffsBefore) {
                resolution.resolvedValues.put(variableSymbol, values);
            }
            return values;
        } finally {
            resolution.inProgress.remove(variableSymbol);
        }
    }

    /** Whether {@code occurrence} is one of the places where {@code variableSymbol} is assigned. */
    private static boolean isWrittenAt(
            @Nonnull Symbol.VariableSymbol variableSymbol, @Nonnull AstNode occurrence) {
        for (Symbol.Usage usage : variableSymbol.usages()) {
            if (usage.node() == occurrence && usage.kind() != Symbol.Usage.UsageKind.READ) {
                return true;
            }
        }
        return false;
    }

    /**
     * Resolves an enum constant to its explicit {@code = constantExpression} value when present,
     * and otherwise to its implicit value: the value of the enumerator before it plus one, or 0 for
     * the first enumerator. When that value is not known, e.g. an enumerator before it is given an
     * undeclared macro, the constant resolves to its own declared name.
     */
    @Nonnull
    private static <O> List<ResolvedValue<O, AstNode>> resolveEnumConstant(
            @Nonnull Class<O> clazz, @Nonnull Symbol constantSymbol) {
        AstNode enumeratorNode = constantSymbol.declaration();
        if (enumeratorNode == null) {
            return Collections.emptyList();
        }
        // The symbol's declaration() is the "enumerator" node (just the IDENTIFIER, plus an
        // optional attribute-specifier-seq); its optional "= constantExpression" is a sibling
        // under the enclosing "enumeratorDefinition" rule, fetched from the parent rather than
        // from the enumerator node itself.
        AstNode enumeratorDefinition = enumeratorNode.getParent();
        if (enumeratorDefinition != null
                && enumeratorDefinition.is(CxxGrammarImpl.enumeratorDefinition)) {
            AstNode constantExpr =
                    enumeratorDefinition.getFirstChild(CxxGrammarImpl.constantExpression);
            if (constantExpr != null) {
                List<ResolvedValue<O, AstNode>> explicitValue =
                        resolveValuesInternal(
                                clazz,
                                constantExpr,
                                new LinkedList<>(),
                                null,
                                false,
                                null,
                                0,
                                new Resolution());
                if (!explicitValue.isEmpty()) {
                    return explicitValue;
                }
            } else {
                final Long implicitValue = implicitEnumeratorValue(enumeratorDefinition);
                if (implicitValue != null) {
                    return castValue(clazz, integerValue(implicitValue))
                            .map(v -> List.of(new ResolvedValue<>(v, enumeratorNode)))
                            .orElse(Collections.emptyList());
                }
            }
        }
        Optional<O> nameValue = castValue(clazz, constantSymbol.name());
        return nameValue
                .map(v -> List.of(new ResolvedValue<>(v, enumeratorNode)))
                .orElse(Collections.emptyList());
    }

    /**
     * The value of an enumerator without a constant expression: the value of the enumerator before
     * it plus one, or 0 for the first enumerator, or null when the value of an enumerator before it
     * is not a known integer.
     */
    @Nullable private static Long implicitEnumeratorValue(@Nonnull AstNode enumeratorDefinition) {
        final AstNode list = enumeratorDefinition.getParent();
        if (list == null) {
            return null;
        }
        long value = -1;
        for (AstNode definition : list.getChildren(CxxGrammarImpl.enumeratorDefinition)) {
            final AstNode constantExpr =
                    definition.getFirstChild(CxxGrammarImpl.constantExpression);
            if (constantExpr == null) {
                value++;
            } else {
                final List<ResolvedValue<Object, AstNode>> explicitValue =
                        resolveValuesInternal(
                                Object.class,
                                constantExpr,
                                new LinkedList<>(),
                                null,
                                false,
                                null,
                                0,
                                new Resolution());
                if (explicitValue.size() != 1
                        || !(explicitValue.get(0).value() instanceof Number number)) {
                    return null;
                }
                value = number.longValue();
            }
            if (definition == enumeratorDefinition) {
                return value;
            }
        }
        return null;
    }

    /**
     * For an identifier that is the right-hand side of a qualified reference ({@code
     * Type::CONSTANT}), looks it up inside the left-hand type's qualified-only member scope when
     * that type is a scoped enum, since a scoped enum's constants are reachable only through their
     * own member scope, not the normal enclosing-scope chain. Returns null for any other {@code
     * nestedNameSpecifier} shape (namespace, class, unresolved type, or an unscoped enum).
     */
    @Nullable private static Symbol resolveScopedEnumConstant(@Nonnull AstNode identifierNode) {
        AstNode qualifiedId = identifierNode.getFirstAncestor(CxxGrammarImpl.qualifiedId);
        if (qualifiedId == null) {
            return null;
        }
        AstNode nestedNameSpecifier = qualifiedId.getFirstChild(CxxGrammarImpl.nestedNameSpecifier);
        if (nestedNameSpecifier == null) {
            return null;
        }
        // "Mode::" parses as nestedNameSpecifier -> typeName -> className -> IDENTIFIER, so the
        // type name token is a descendant, not a direct child
        AstNode typeNameNode = nestedNameSpecifier.getFirstDescendant(GenericTokenType.IDENTIFIER);
        if (typeNameNode == null
                || !(AstNodeSymbolExtension.getSymbol(typeNameNode)
                        instanceof Symbol.TypeSymbol typeSymbol)
                || !typeSymbol.isScopedEnum()) {
            return null;
        }
        SymbolTable memberScope = typeSymbol.memberScope();
        if (memberScope == null) {
            return null;
        }
        return memberScope.getSymbol(identifierNode.getTokenValue());
    }

    @Nonnull
    private static <O> List<ResolvedValue<O, AstNode>> resolvePrimaryExpression(
            @Nonnull Class<O> clazz,
            @Nonnull AstNode tree,
            @Nonnull LinkedList<AstNode> selections,
            @Nullable IValueFactory<AstNode> valueFactory,
            boolean returnEnclosingParam,
            @Nullable CxxDetectionEngine detectionEngine,
            int depth,
            @Nonnull Resolution resolution) {
        // "( expression )": the value of the expression
        if (tree.getNumberOfChildren() == 3 && tree.getFirstChild().is(CxxPunctuator.BR_LEFT)) {
            return resolveValuesInternal(
                    clazz,
                    tree.getChildren().get(1),
                    selections,
                    valueFactory,
                    returnEnclosingParam,
                    detectionEngine,
                    depth + 1,
                    resolution);
        }

        AstNode literal = tree.getFirstChild(CxxGrammarImpl.LITERAL);
        if (literal != null) {
            return resolveLiteral(
                    clazz,
                    literal,
                    selections,
                    valueFactory,
                    returnEnclosingParam,
                    detectionEngine,
                    depth,
                    resolution);
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
                    depth + 1,
                    resolution);
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
            int depth,
            @Nonnull Resolution resolution) {
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
                    depth + 1,
                    resolution);
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
            int depth,
            @Nonnull Resolution resolution) {
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
                    depth + 1,
                    resolution);
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
            int depth,
            @Nonnull Resolution resolution) {
        AstNode assignmentExpression = tree.getFirstChild(CxxGrammarImpl.assignmentExpression);
        if (assignmentExpression != null) {
            return resolveAssignmentExpression(
                    clazz,
                    assignmentExpression,
                    selections,
                    valueFactory,
                    returnEnclosingParam,
                    detectionEngine,
                    depth,
                    resolution);
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
                    depth + 1,
                    resolution);
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
            int depth,
            @Nonnull Resolution resolution) {
        AstNode firstChild = tree.getFirstChild();
        if (firstChild != null) {
            return resolveValuesInternal(
                    clazz,
                    firstChild,
                    selections,
                    valueFactory,
                    returnEnclosingParam,
                    detectionEngine,
                    depth + 1,
                    resolution);
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
        // A function call's callee name is not itself a resolved value. A plain function-call
        // identifier has a method symbol, not a variable or enum symbol, so none of the
        // IDENTIFIER sub-cases in resolveIdentifier apply to it, and resolution yields nothing.
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

    /**
     * The state of resolving one expression: the variables being resolved, the values of the
     * variables resolved completely, and how often the depth limit or the cycle guard left a value
     * out.
     */
    private static final class Resolution {
        @Nonnull private final Set<Symbol.VariableSymbol> inProgress = new HashSet<>();

        @Nonnull
        private final Map<Symbol.VariableSymbol, List<? extends ResolvedValue<?, AstNode>>>
                resolvedValues = new HashMap<>();

        private int cutOffs;

        /**
         * The values {@code variableSymbol} was resolved to, or null if it was not resolved
         * completely yet. All values of a resolution are of the class it was started with.
         */
        @SuppressWarnings("unchecked")
        @Nullable private <O> List<ResolvedValue<O, AstNode>> valuesOf(
                @Nonnull Symbol.VariableSymbol variableSymbol) {
            return (List<ResolvedValue<O, AstNode>>) resolvedValues.get(variableSymbol);
        }
    }
}
