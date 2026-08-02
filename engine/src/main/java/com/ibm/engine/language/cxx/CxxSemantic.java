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
import org.sonar.cxx.squidbridge.api.AstNodeSymbolExtension;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.api.SymbolTable;
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
                        depth + 1);
            }
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

    /**
     * A brace-enclosed initializer list (e.g. an {@code OSSL_PARAM params[] = {...}} array) has no
     * single scalar value to resolve; the {@code bracedInitList} node itself is resolved as-is, so
     * a value factory that understands the specific struct-array shape (via {@link
     * ResolvedValue#value()}) can scan its elements when applied downstream.
     */
    @Nonnull
    private static <O> List<ResolvedValue<O, AstNode>> resolveBracedInitList(
            @Nonnull Class<O> clazz, @Nonnull AstNode tree) {
        return castValue(clazz, tree)
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
            LOGGER.debug("Could not resolve identifier '{}' as constant: {}", name, e.getMessage());
        }

        // A field's or parameter's own name is never a resolved value. Parameters are still
        // returned when returnEnclosingParam is set, since that caller needs the node to hook the
        // enclosing function; a field has nothing to hook. A scoped enum's constants live only in
        // its qualified-only member scope (see Symbol.TypeSymbol#memberScope), so a qualified
        // reference (Mode::STRICT) is looked up there first, since the normal scope-chain lookup
        // never finds a symbol that was never registered in an enclosing scope.
        Symbol symbol = resolveScopedEnumConstant(tree, detectionEngine);
        if (symbol == null) {
            symbol = AstNodeSymbolExtension.getSymbol(tree);
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
                            depth);
            if (!chased.isEmpty()) {
                return chased;
            }
        } else if (symbol != null
                && symbol.kind() == Symbol.Kind.ENUM_CONSTANT
                && !symbol.isUnknown()) {
            List<ResolvedValue<O, AstNode>> resolved = resolveEnumConstant(clazz, symbol);
            if (!resolved.isEmpty()) {
                return resolved;
            }
        }

        // An identifier with no attached symbol at all (an undeclared name: an external constant,
        // a macro, something declared in another translation unit) is not itself a resolved value;
        // resolution of such names is deferred to the separate outer-scope resolution mechanism.
        return Collections.emptyList();
    }

    /**
     * Resolves a variable to its declaration-time initializer value and every subsequent
     * reassignment's value, matching how the Java engine chases {@code VariableTree.initializer()}
     * and assignment-site usages. The initializer's result (if any) comes first, followed by
     * reassignments in source order; an empty list means neither yielded a resolved value.
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
            int depth) {
        LinkedList<ResolvedValue<O, AstNode>> result = new LinkedList<>();

        for (Symbol.Usage usage : variableSymbol.usages()) {
            if (usage.node() == currentOccurrence) {
                continue;
            }
            if (usage.kind() != Symbol.Usage.UsageKind.WRITE
                    && usage.kind() != Symbol.Usage.UsageKind.READ_WRITE) {
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
                            depth + 1));
        }

        AstNode initializer = variableSymbol.initializer();
        if (initializer != null) {
            // braceOrEqualInitializer is declared with .skip() and initializerClause with
            // .skipIfOneChild(), so for a plain "= <value>" declarator neither node survives in the
            // tree: initializer ends up with the "=" token as its first child and the (possibly
            // further-collapsed) value expression as its last child. Taking the structurally last
            // child, as with assignmentExpression above, reaches the value regardless of how far
            // it collapsed.
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
                            depth + 1);
            result.addAll(0, initializerResults);
        }

        return result;
    }

    /**
     * Resolves an enum constant to its explicit {@code = constantExpression} value when present,
     * falling back to the constant's own declared name otherwise. A bare enum-constant reference
     * with no explicit value is still a real, useful resolved value: the constant's own name.
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
                                clazz, constantExpr, new LinkedList<>(), null, false, null, 0);
                if (!explicitValue.isEmpty()) {
                    return explicitValue;
                }
            }
        }
        Optional<O> nameValue = castValue(clazz, constantSymbol.name());
        return nameValue
                .map(v -> List.of(new ResolvedValue<>(v, enumeratorNode)))
                .orElse(Collections.emptyList());
    }

    /**
     * For an identifier that is the right-hand side of a qualified reference ({@code
     * Type::CONSTANT}), looks it up inside the left-hand type's qualified-only member scope when
     * that type is a scoped enum, since a scoped enum's constants are reachable only through their
     * own member scope, not the normal enclosing-scope chain. Returns null for any other {@code
     * nestedNameSpecifier} shape (namespace, class, unresolved type, or an unscoped enum), leaving
     * those for the normal lookup path or a future, more general qualified-name resolution to
     * handle.
     */
    @Nullable private static Symbol resolveScopedEnumConstant(
            @Nonnull AstNode identifierNode, @Nullable CxxDetectionEngine detectionEngine) {
        AstNode qualifiedId = identifierNode.getFirstAncestor(CxxGrammarImpl.qualifiedId);
        if (qualifiedId == null) {
            return null;
        }
        AstNode nestedNameSpecifier = qualifiedId.getFirstChild(CxxGrammarImpl.nestedNameSpecifier);
        if (nestedNameSpecifier == null) {
            return null;
        }
        // nestedNameSpecifier does not carry a bare IDENTIFIER child directly for a type-qualified
        // reference; "Mode::" parses as nestedNameSpecifier -> typeName -> className -> IDENTIFIER,
        // so the type name token has to be found as a descendant, not a direct child.
        AstNode typeNameNode = nestedNameSpecifier.getFirstDescendant(GenericTokenType.IDENTIFIER);
        if (typeNameNode == null) {
            return null;
        }
        // A className-wrapped type-name reference (as opposed to a declarator/usage-site
        // identifier) is never given its own attached Symbol by CxxSymbolResolverVisitor, since
        // isInsideDeclarator(...) treats any className ancestor as a declaration site and skips
        // usage resolution for it, even though this occurrence is a genuine read. The type symbol
        // is still registered by name in the enclosing scope table, so it is found by a
        // name-based scope lookup rather than an AstNode-to-Symbol association.
        Symbol typeSymbolCandidate = AstNodeSymbolExtension.getSymbol(typeNameNode);
        if (typeSymbolCandidate == null) {
            SymbolTable rootScope = rootSymbolTable(detectionEngine);
            if (rootScope != null) {
                typeSymbolCandidate = rootScope.lookupSymbol(typeNameNode.getTokenValue());
            }
        }
        if (!(typeSymbolCandidate instanceof Symbol.TypeSymbol typeSymbol)
                || !typeSymbol.isScopedEnum()) {
            return null;
        }
        SymbolTable memberScope = typeSymbol.memberScope();
        if (memberScope == null) {
            return null;
        }
        return memberScope.getSymbol(identifierNode.getTokenValue());
    }

    /**
     * The file's root {@code SymbolTable}, reached through the scan context rather than any
     * particular {@code AstNode}, since a qualified reference's left-hand type name has no attached
     * symbol of its own to start a lookup from (see {@link #resolveScopedEnumConstant}).
     */
    @Nullable private static SymbolTable rootSymbolTable(@Nullable CxxDetectionEngine detectionEngine) {
        if (detectionEngine == null) {
            return null;
        }
        if (detectionEngine.getScanContext() instanceof CxxScanContext cxxScanContext) {
            return cxxScanContext.cxxVisitorContext().getSymbolTable();
        }
        return null;
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
}
