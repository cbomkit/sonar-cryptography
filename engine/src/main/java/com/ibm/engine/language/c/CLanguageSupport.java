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
package com.ibm.engine.language.c;

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
import com.ibm.engine.language.c.tree.CFunctionCallTree;
import com.ibm.engine.language.c.tree.CTree;
import com.ibm.engine.rule.IDetectionRule;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Language support implementation for C/C++.
 *
 * <p>Mirrors {@code CSharpLanguageSupport}: wires together the {@link CLanguageTranslation}, {@link
 * CDetectionEngine}, and {@link CBaseMethodVisitor} using the shared {@link Handler} and {@link
 * DetectionExecutive} infrastructure.
 */
public final class CLanguageSupport
        implements ILanguageSupport<CCheck, CTree, CSymbol, CScanContext> {

    @Nonnull private final Handler<CCheck, CTree, CSymbol, CScanContext> handler;

    @Nonnull private final CLanguageTranslation translation;

    public CLanguageSupport() {
        this.handler = new Handler<>(this);
        this.translation = new CLanguageTranslation();
    }

    @Nonnull
    @Override
    public ILanguageTranslation<CTree> translation() {
        return translation;
    }

    @Nonnull
    @Override
    public DetectionExecutive<CCheck, CTree, CSymbol, CScanContext> createDetectionExecutive(
            @Nonnull CTree tree,
            @Nonnull IDetectionRule<CTree> detectionRule,
            @Nonnull IScanContext<CCheck, CTree> scanContext) {
        return new DetectionExecutive<>(tree, detectionRule, scanContext, this.handler);
    }

    @Nonnull
    @Override
    public IDetectionEngine<CTree, CSymbol> createDetectionEngineInstance(
            @Nonnull DetectionStore<CCheck, CTree, CSymbol, CScanContext> detectionStore) {
        return new CDetectionEngine(detectionStore, this.handler);
    }

    @Nonnull
    @Override
    public IBaseMethodVisitorFactory<CTree, CSymbol> getBaseMethodVisitorFactory() {
        return CBaseMethodVisitor::new;
    }

    @Nonnull
    @Override
    public Optional<CTree> getEnclosingMethod(@Nonnull CTree expression) {
        if (expression instanceof CFunctionCallTree call && call.getEnclosingBlock() != null) {
            return Optional.of(call.getEnclosingBlock());
        }
        return Optional.empty();
    }

    @Nullable @Override
    public MethodMatcher<CTree> createMethodMatcherBasedOn(@Nonnull CTree methodDefinition) {
        // Inter-procedural method matching not supported without semantic analysis
        return null;
    }

    @Nullable @Override
    public EnumMatcher<CTree> createSimpleEnumMatcherFor(
            @Nonnull CTree enumIdentifier, @Nonnull MatchContext matchContext) {
        Optional<String> name = translation().getEnumIdentifierName(matchContext, enumIdentifier);
        return name.<EnumMatcher<CTree>>map(EnumMatcher::new).orElse(null);
    }
}
