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

    public CxxLanguageSupport() {
        this.handler = new Handler<>(this);
    }

    @Nonnull
    @Override
    public ILanguageTranslation<AstNode> translation() {
        return new CxxLanguageTranslation();
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

            AstNode enclosingClass = CxxAstNodeHelper.getEnclosingClass(methodDefinition);
            String invocationObjectName;
            if (enclosingClass != null) {
                String className = CxxAstNodeHelper.getIdentifierName(enclosingClass);
                invocationObjectName = className != null ? className : "";
            } else {
                invocationObjectName = "";
            }

            List<AstNode> parameters =
                    CxxAstNodeHelper.getFunctionDefinitionParameters(methodDefinition);
            LinkedList<String> parameterTypeList = new LinkedList<>();
            for (AstNode param : parameters) {
                AstNode declSpecifierSeq =
                        param.getFirstChild(CxxGrammarImpl.parameterDeclSpecifierSeq);
                if (declSpecifierSeq != null) {
                    StringBuilder sb = new StringBuilder();
                    for (var token : declSpecifierSeq.getTokens()) {
                        sb.append(token.getValue());
                    }
                    parameterTypeList.add(sb.toString().trim());
                } else {
                    parameterTypeList.add("*");
                }
            }

            return new MethodMatcher<>(invocationObjectName, functionName, parameterTypeList);
        } catch (Exception e) {
            LOGGER.error(e.getLocalizedMessage());
            return null;
        }
    }

    @Nullable @Override
    public EnumMatcher<AstNode> createSimpleEnumMatcherFor(
            @Nonnull AstNode enumIdentifier, @Nonnull MatchContext matchContext) {
        Optional<String> enumIdentifierName =
                translation().getEnumIdentifierName(matchContext, enumIdentifier);
        return enumIdentifierName.<EnumMatcher<AstNode>>map(EnumMatcher::new).orElse(null);
    }
}
