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

import com.ibm.engine.detection.IType;
import com.ibm.engine.detection.MatchContext;
import com.ibm.engine.language.ILanguageTranslation;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.GenericTokenType;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.cxx.parser.CxxGrammarImpl;
import org.sonar.cxx.parser.CxxTokenType;
import org.sonar.cxx.squidbridge.api.AstNodeSymbolExtension;
import org.sonar.cxx.squidbridge.api.AstNodeTypeExtension;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.api.Type;
import org.sonar.cxx.utils.CxxAstNodeHelper;

public class CxxLanguageTranslation implements ILanguageTranslation<AstNode> {
    @Nonnull
    private static final Logger LOGGER = LoggerFactory.getLogger(CxxLanguageTranslation.class);

    /**
     * Synthetic type name used for standalone C/C++ function calls that have no object qualifier.
     * Detection rules for C-style functions (e.g., OpenSSL's EVP_DigestInit_ex) should use {@code
     * forObjectTypes("*")} to match any type, or {@code forObjectTypes("<global>")} to match only
     * standalone function calls.
     */
    public static final String GLOBAL_SCOPE = "<global>";

    @Nonnull
    @Override
    public Optional<String> getMethodName(
            @Nonnull MatchContext matchContext, @Nonnull AstNode methodInvocation) {
        if (CxxAstNodeHelper.isFunctionCall(methodInvocation)) {
            String name = CxxAstNodeHelper.getFunctionCallName(methodInvocation);
            if (name != null) {
                return Optional.of(name);
            }
        } else if (CxxAstNodeHelper.isConstructorCall(methodInvocation)) {
            return Optional.of("<init>");
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<IType> getInvokedObjectTypeString(
            @Nonnull MatchContext matchContext, @Nonnull AstNode methodInvocation) {
        if (CxxAstNodeHelper.isMemberAccess(methodInvocation)) {
            AstNode qualifier = CxxAstNodeHelper.getMemberAccessQualifier(methodInvocation);
            if (qualifier != null) {
                Type cxxType = AstNodeTypeExtension.getType(qualifier);
                if (cxxType != null && !cxxType.isUnknown()) {
                    return Optional.of(createTypeFromCxxType(cxxType, matchContext));
                }

                Symbol symbol = AstNodeSymbolExtension.getSymbol(qualifier);
                if (symbol != null && !symbol.isUnknown()) {
                    String fqn = symbol.fullyQualifiedName();
                    if (fqn != null) {
                        return Optional.of(createTypeFromFqn(fqn, matchContext));
                    }
                }

                String identifierName = CxxAstNodeHelper.getIdentifierName(qualifier);
                if (identifierName != null) {
                    return Optional.of(createTypeFromFqn(identifierName, matchContext));
                }
            }
        } else if (CxxAstNodeHelper.isConstructorCall(methodInvocation)) {
            AstNode newTypeId = methodInvocation.getFirstChild(CxxGrammarImpl.newTypeId);
            if (newTypeId != null) {
                Type cxxType = AstNodeTypeExtension.getType(newTypeId);
                if (cxxType != null && !cxxType.isUnknown()) {
                    return Optional.of(createTypeFromCxxType(cxxType, matchContext));
                }

                String typeName = extractTypeName(newTypeId);
                if (typeName != null) {
                    return Optional.of(createTypeFromFqn(typeName, matchContext));
                }
            }
        } else if (CxxAstNodeHelper.isFunctionCall(methodInvocation)) {
            // Standalone C/C++ function call (no member access qualifier).
            // Return a synthetic global scope type so MethodMatcher.match() doesn't
            // short-circuit on empty. Detection rules should use forObjectTypes("*").
            return Optional.of(createTypeFromFqn(GLOBAL_SCOPE, matchContext));
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<IType> getMethodReturnTypeString(
            @Nonnull MatchContext matchContext, @Nonnull AstNode methodInvocation) {
        if (CxxAstNodeHelper.isFunctionCall(methodInvocation)) {
            Type cxxType = AstNodeTypeExtension.getType(methodInvocation);
            if (cxxType != null && !cxxType.isUnknown()) {
                return Optional.of(createTypeFromCxxType(cxxType, matchContext));
            }

            AstNode idExpr = methodInvocation.getFirstDescendant(CxxGrammarImpl.idExpression);
            if (idExpr != null) {
                Symbol symbol = AstNodeSymbolExtension.getSymbol(idExpr);
                if (symbol != null
                        && symbol.isFunctionSymbol()
                        && symbol instanceof Symbol.FunctionSymbol funcSym) {
                    Type returnType = funcSym.returnType();
                    if (returnType != null && !returnType.isUnknown()) {
                        return Optional.of(createTypeFromCxxType(returnType, matchContext));
                    }
                }
            }
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public List<IType> getMethodParameterTypes(
            @Nonnull MatchContext matchContext, @Nonnull AstNode methodInvocation) {
        List<AstNode> arguments;

        if (CxxAstNodeHelper.isFunctionCall(methodInvocation)) {
            arguments = extractActualArguments(methodInvocation);
        } else if (CxxAstNodeHelper.isConstructorCall(methodInvocation)) {
            AstNode newInitializer = methodInvocation.getFirstChild(CxxGrammarImpl.newInitializer);
            if (newInitializer != null) {
                AstNode expressionList =
                        newInitializer.getFirstDescendant(CxxGrammarImpl.expressionList);
                if (expressionList != null) {
                    arguments = flattenInitializerList(expressionList);
                } else {
                    arguments = Collections.emptyList();
                }
            } else {
                arguments = Collections.emptyList();
            }
        } else {
            return Collections.emptyList();
        }

        if (arguments.isEmpty()) {
            return Collections.emptyList();
        }

        List<IType> types = new ArrayList<>();
        List<Boolean> parameterMatchExactTypes = matchContext.parametersShouldMatchExactTypes();
        List<Boolean> matchMatrix = parameterMatchExactTypes;

        if (parameterMatchExactTypes.size() != arguments.size()) {
            Boolean[] defaults = new Boolean[arguments.size()];
            java.util.Arrays.fill(defaults, Boolean.FALSE);
            matchMatrix = java.util.Arrays.asList(defaults);
        }

        for (int i = 0; i < arguments.size(); i++) {
            AstNode argument = arguments.get(i);
            boolean exactMatch = matchMatrix.get(i);

            String literalText = extractLiteralText(argument);
            if (literalText != null) {
                types.add(createTypeFromLiteralText(literalText));
                continue;
            }

            String identifierName = extractIdentifierText(argument);
            if (identifierName != null) {
                types.add(createTypeFromLiteralText(identifierName));
                continue;
            }

            Type argType = AstNodeTypeExtension.getType(argument);
            if (argType != null && !argType.isUnknown()) {
                types.add(
                        createTypeFromCxxType(
                                argType,
                                new MatchContext(
                                        matchContext.isHookContext(),
                                        exactMatch,
                                        Collections.emptyList())));
                continue;
            }

            Symbol argSymbol = AstNodeSymbolExtension.getSymbol(argument);
            if (argSymbol != null && !argSymbol.isUnknown()) {
                String fqn = argSymbol.fullyQualifiedName();
                if (fqn != null) {
                    types.add(
                            createTypeFromFqn(
                                    fqn,
                                    new MatchContext(
                                            matchContext.isHookContext(),
                                            exactMatch,
                                            Collections.emptyList())));
                    continue;
                }
            }

            types.add(createUnknownType());
        }
        return types;
    }

    @Nonnull
    @Override
    public Optional<String> resolveIdentifierAsString(
            @Nonnull MatchContext matchContext, @Nonnull AstNode identifier) {
        if (identifier.is(GenericTokenType.IDENTIFIER)) {
            return Optional.of(identifier.getTokenValue());
        }
        String name = CxxAstNodeHelper.getIdentifierName(identifier);
        if (name != null) {
            return Optional.of(name);
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<String> getEnumIdentifierName(
            @Nonnull MatchContext matchContext, @Nonnull AstNode enumIdentifier) {
        if (enumIdentifier.is(GenericTokenType.IDENTIFIER)) {
            return Optional.of(enumIdentifier.getTokenValue());
        }
        String name = CxxAstNodeHelper.getIdentifierName(enumIdentifier);
        if (name != null) {
            return Optional.of(name);
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<String> getEnumClassName(
            @Nonnull MatchContext matchContext, @Nonnull AstNode enumClass) {
        if (enumClass.is(CxxGrammarImpl.enumSpecifier)) {
            AstNode enumHead = enumClass.getFirstChild(CxxGrammarImpl.enumHead);
            if (enumHead != null) {
                AstNode enumHeadName = enumHead.getFirstChild(CxxGrammarImpl.enumHeadName);
                if (enumHeadName != null) {
                    String name = CxxAstNodeHelper.getIdentifierName(enumHeadName);
                    if (name != null) {
                        return Optional.of(name);
                    }
                }
            }
        }
        return Optional.empty();
    }

    /**
     * Extracts actual argument nodes from a function call postfixExpression.
     *
     * <p>Works around sonar-cxx's {@code CxxAstNodeHelper.getFunctionCallArguments()}, which
     * returns the children of {@code expressionList}. In sonar-cxx grammar, {@code expressionList =
     * initializerList}, and {@code initializerList = initializerClause (',' initializerClause)*}.
     * Walking only to {@code expressionList.getChildren()} yields a single {@code initializerList}
     * wrapper node, not the individual argument expressions. This method descends into the {@code
     * initializerList} and returns the actual {@code initializerClause} children (skipping comma
     * tokens).
     */
    @Nonnull
    private List<AstNode> extractActualArguments(@Nonnull AstNode methodInvocation) {
        AstNode expressionList = methodInvocation.getFirstDescendant(CxxGrammarImpl.expressionList);
        if (expressionList == null) {
            return Collections.emptyList();
        }
        return flattenInitializerList(expressionList);
    }

    @Nonnull
    private List<AstNode> flattenInitializerList(@Nonnull AstNode expressionList) {
        AstNode initList = expressionList.getFirstChild(CxxGrammarImpl.initializerList);
        if (initList == null) {
            return expressionList.getChildren();
        }
        List<AstNode> out = new ArrayList<>();
        for (AstNode child : initList.getChildren()) {
            if (",".equals(child.getTokenValue())) {
                continue;
            }
            out.add(child);
        }
        return out;
    }

    /**
     * Extracts the source text of a literal argument. Returns the raw token text (with surrounding
     * quotes for string literals) so rules can match e.g. {@code
     * withMethodParameter("\"CTR-DRBG\"")}. Returns null when the argument is not a literal.
     */
    private String extractLiteralText(@Nonnull AstNode argument) {
        AstNode literal = argument;
        if (!literal.is(CxxGrammarImpl.LITERAL)) {
            literal = argument.getFirstDescendant(CxxGrammarImpl.LITERAL);
        }
        if (literal != null) {
            StringBuilder sb = new StringBuilder();
            for (var token : literal.getTokens()) {
                sb.append(token.getValue());
            }
            String text = sb.toString().trim();
            if (!text.isEmpty()) {
                return text;
            }
        }
        // Fallback: check for raw STRING/NUMBER/CHARACTER tokens (used when argument is
        // the initializerClause wrapping a literal expression directly).
        if ("STRING".equals(String.valueOf(argument.getType()))
                || "NUMBER".equals(String.valueOf(argument.getType()))
                || "CHARACTER".equals(String.valueOf(argument.getType()))) {
            String text = argument.getTokenValue();
            return (text == null || text.isEmpty()) ? null : text;
        }
        // Walk down for STRING/NUMBER/CHARACTER tokens inside initializerClause.
        for (AstNode d :
                argument.getDescendants(
                        CxxTokenType.STRING, CxxTokenType.NUMBER, CxxTokenType.CHARACTER)) {
            String text = d.getTokenValue();
            if (text != null && !text.isEmpty()) {
                return text;
            }
        }
        return null;
    }

    private IType createTypeFromLiteralText(@Nonnull String literalText) {
        return typeString -> literalText.equals(typeString);
    }

    /**
     * Extracts the text of an IDENTIFIER argument (e.g. a macro / const / enum constant name passed
     * as a function argument). Rules can then match by identifier name via {@code
     * .withMethodParameter("EVP_PKEY_DH")}. Returns null if the argument is not a plain identifier
     * expression.
     */
    private String extractIdentifierText(@Nonnull AstNode argument) {
        // Only match if subtree contains a single IDENTIFIER leaf (plain identifier arg).
        AstNode cur = argument;
        while (cur != null && !cur.getChildren().isEmpty()) {
            if (cur.getChildren().size() != 1) {
                return null;
            }
            cur = cur.getChildren().get(0);
        }
        if (cur != null && "IDENTIFIER".equals(String.valueOf(cur.getType()))) {
            String text = cur.getTokenValue();
            if (text != null && !text.isEmpty()) {
                return text;
            }
        }
        return null;
    }

    IType createTypeFromCxxType(@Nonnull Type cxxType, @Nonnull MatchContext matchContext) {
        final String fqn = cxxType.fullyQualifiedName();
        final boolean exactOnly =
                matchContext.isHookContext() || matchContext.objectShouldMatchExactTypes();
        if (exactOnly) {
            return typeString -> fqn != null && fqn.equals(typeString);
        }

        final Symbol.TypeSymbol typeSymbol = cxxType.symbol();
        final List<String> baseFqns = new ArrayList<>();
        if (typeSymbol != null) {
            for (Symbol.TypeSymbol base : typeSymbol.baseClasses()) {
                String baseFqn = base.fullyQualifiedName();
                if (baseFqn != null) {
                    baseFqns.add(baseFqn);
                }
            }
        }
        return typeString ->
                (fqn != null && fqn.equals(typeString)) || baseFqns.contains(typeString);
    }

    private IType createTypeFromFqn(@Nonnull String fqn, @Nonnull MatchContext matchContext) {
        return typeString -> {
            if (matchContext.isHookContext() || matchContext.objectShouldMatchExactTypes()) {
                return fqn.equals(typeString);
            }
            return fqn.equals(typeString)
                    || fqn.endsWith("::" + typeString)
                    || typeString.endsWith("::" + fqn);
        };
    }

    private IType createUnknownType() {
        return typeString -> false;
    }

    private String extractTypeName(AstNode typeNode) {
        if (typeNode == null) {
            return null;
        }
        AstNode typeSpecifierSeq = typeNode.getFirstDescendant(CxxGrammarImpl.typeSpecifierSeq);
        if (typeSpecifierSeq != null) {
            AstNode simpleTypeSpecifier =
                    typeSpecifierSeq.getFirstDescendant(CxxGrammarImpl.simpleTypeSpecifier);
            if (simpleTypeSpecifier != null) {
                StringBuilder sb = new StringBuilder();
                for (var token : simpleTypeSpecifier.getTokens()) {
                    sb.append(token.getValue());
                }
                return sb.toString().trim();
            }
        }
        return CxxAstNodeHelper.getIdentifierName(typeNode);
    }
}
