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

import com.ibm.engine.callstack.CallContextStats;
import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.detection.EnumMatcher;
import com.ibm.engine.detection.Handler;
import com.ibm.engine.detection.IBaseMethodVisitorFactory;
import com.ibm.engine.detection.IDetectionEngine;
import com.ibm.engine.detection.MatchContext;
import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.executive.DetectionExecutive;
import com.ibm.engine.language.ILanguageSupport;
import com.ibm.engine.language.ILanguageTranslation;
import com.ibm.engine.language.IScanContext;
import com.ibm.engine.rule.IDetectionRule;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.cxx.parser.CxxGrammarImpl;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;
import org.sonar.cxx.utils.CxxAstNodeHelper;

public final class CxxLanguageSupport
        implements ILanguageSupport<
                SquidCheck<?>, AstNode, Symbol, SquidAstVisitorContext<? extends Grammar>> {
    private static final Logger LOGGER = LoggerFactory.getLogger(CxxLanguageSupport.class);

    @Nonnull
    private final Handler<SquidCheck<?>, AstNode, Symbol, SquidAstVisitorContext<? extends Grammar>>
            handler;

    @Nonnull private final CxxLanguageTranslation translation;

    public CxxLanguageSupport() {
        this.handler = new Handler<>(this);
        this.translation = new CxxLanguageTranslation();
    }

    @Nonnull
    @Override
    public ILanguageTranslation<AstNode> translation() {
        return translation;
    }

    @Nonnull
    @Override
    public DetectionExecutive<
                    SquidCheck<?>, AstNode, Symbol, SquidAstVisitorContext<? extends Grammar>>
            createDetectionExecutive(
                    @Nonnull AstNode tree,
                    @Nonnull IDetectionRule<AstNode> detectionRule,
                    @Nonnull IScanContext<SquidCheck<?>, AstNode> scanContext) {
        return new DetectionExecutive<>(tree, detectionRule, scanContext, this.handler);
    }

    @Nonnull
    @Override
    public IDetectionEngine<AstNode, Symbol> createDetectionEngineInstance(
            @Nonnull
                    DetectionStore<
                                    SquidCheck<?>,
                                    AstNode,
                                    Symbol,
                                    SquidAstVisitorContext<? extends Grammar>>
                            detectionStore) {
        return new CxxDetectionEngine(detectionStore, this.handler);
    }

    @Nonnull
    @Override
    public IBaseMethodVisitorFactory<AstNode, Symbol> getBaseMethodVisitorFactory() {
        return CxxBaseMethodVisitor::new;
    }

    @Nonnull
    @Override
    public Optional<AstNode> getEnclosingMethod(@Nonnull AstNode expression) {
        AstNode enclosingFunction = CxxAstNodeHelper.getEnclosingFunction(expression);
        return Optional.ofNullable(enclosingFunction);
    }

    @Nullable @Override
    public MethodMatcher<AstNode> createMethodMatcherBasedOn(@Nonnull AstNode methodDefinition) {
        if (!methodDefinition.is(CxxGrammarImpl.functionDefinition)) {
            return null;
        }

        try {
            String functionName = CxxAstNodeHelper.getFunctionDefinitionName(methodDefinition);
            if (functionName == null) {
                return null;
            }

            // A member function is defined in its class, or outside it with a name qualified by
            // the class, e.g. Hasher::reset; the class is named with the namespaces and classes
            // it is declared in. A constructor is called as <init> of its class, see
            // CxxLanguageTranslation#getMethodName.
            final String className = CxxScopes.classOfFunction(methodDefinition);
            String invocationObjectName;
            if (className != null) {
                invocationObjectName = className;
                functionName = unqualified(functionName);
                if (functionName.equals(unqualified(className))) {
                    functionName = "<init>";
                }
            } else {
                // Standalone functions use the same synthetic scope name as
                // CxxLanguageTranslation#getInvokedObjectTypeString for a call site, and are
                // named with the namespaces they are declared in, as a call names them (see
                // CxxScopes#lookupNames)
                invocationObjectName = CxxLanguageTranslation.GLOBAL_SCOPE;
                final List<String> namespaces = CxxScopes.enclosingNamespaces(methodDefinition);
                if (!namespaces.isEmpty()) {
                    functionName = String.join("::", namespaces) + "::" + functionName;
                }
            }

            // Parameter types are wildcards: CxxLanguageTranslation#getMethodParameterTypes
            // derives a call site's argument types from literal/identifier content, not from
            // declared C++ types, so the two are not comparable. Only parameter count is matched.
            List<AstNode> parameters =
                    CxxAstNodeHelper.getFunctionDefinitionParameters(methodDefinition);
            LinkedList<String> parameterTypeList = new LinkedList<>();
            for (int i = 0; i < parameters.size(); i++) {
                parameterTypeList.add(MethodMatcher.ANY);
            }

            return new MethodMatcher<>(invocationObjectName, functionName, parameterTypeList);
        } catch (Exception e) {
            LOGGER.error(e.getLocalizedMessage(), e);
            return null;
        }
    }

    /** The last component of a qualified name, {@code reset} of {@code Hasher::reset}. */
    @Nonnull
    private static String unqualified(@Nonnull String name) {
        final int separator = name.lastIndexOf("::");
        return separator < 0 ? name : name.substring(separator + 2);
    }

    @Nullable @Override
    public EnumMatcher<AstNode> createSimpleEnumMatcherFor(
            @Nonnull AstNode enumIdentifier, @Nonnull MatchContext matchContext) {
        Optional<String> enumIdentifierName =
                translation().getEnumIdentifierName(matchContext, enumIdentifier);
        return enumIdentifierName.<EnumMatcher<AstNode>>map(EnumMatcher::new).orElse(null);
    }

    @Override
    public void notifyLeaveFile(@Nonnull InputFile inputFile) {
        this.handler.detachCallsForFile(inputFile);
    }

    @Nonnull
    @Override
    public CallContextStats callContextStats() {
        return this.handler.callContextStats();
    }

    @Override
    public boolean isDetachableCall(@Nonnull AstNode tree) {
        // the values of the arguments of a call of a function or a constructor hold no syntax
        // tree, a braced-init-list included (see CxxSemantic#resolveValues)
        return CxxAstNodeHelper.isFunctionCall(tree) || CxxConstructorCalls.isConstructorCall(tree);
    }

    @Override
    public int parameterIndexOf(
            @Nonnull AstNode methodDefinition, @Nonnull AstNode methodParameter) {
        if (!methodDefinition.is(CxxGrammarImpl.functionDefinition)) {
            return -1;
        }
        final Optional<String> targetName =
                translation()
                        .resolveIdentifierAsString(
                                MatchContext.createForHookContext(), methodParameter);
        if (targetName.isEmpty()) {
            return -1;
        }
        final List<AstNode> parameters =
                CxxAstNodeHelper.getFunctionDefinitionParameters(methodDefinition);
        for (int i = 0; i < parameters.size(); i++) {
            final String paramName = CxxAstNodeHelper.getIdentifierName(parameters.get(i));
            if (targetName.get().equals(paramName)) {
                return i;
            }
        }
        return -1;
    }
}
