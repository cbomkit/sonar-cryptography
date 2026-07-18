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
package com.ibm.engine.language.csharp;

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
import com.ibm.engine.language.csharp.tree.CSharpMethodInvocationTree;
import com.ibm.engine.language.csharp.tree.CSharpObjectCreationTree;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.rule.IDetectionRule;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Language support implementation for C#.
 *
 * <p>Mirrors {@code GoLanguageSupport}: wires together the {@link CSharpLanguageTranslation},
 * {@link CSharpDetectionEngine}, and {@link CSharpBaseMethodVisitor} using the shared {@link
 * Handler} and {@link DetectionExecutive} infrastructure.
 */
public final class CSharpLanguageSupport
        implements ILanguageSupport<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> {

    @Nonnull
    private final Handler<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> handler;

    @Nonnull private final CSharpLanguageTranslation translation;

    public CSharpLanguageSupport() {
        this.handler = new Handler<>(this);
        this.translation = new CSharpLanguageTranslation();
    }

    @Nonnull
    @Override
    public ILanguageTranslation<CSharpTree> translation() {
        return translation;
    }

    @Nonnull
    @Override
    public DetectionExecutive<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
            createDetectionExecutive(
                    @Nonnull CSharpTree tree,
                    @Nonnull IDetectionRule<CSharpTree> detectionRule,
                    @Nonnull IScanContext<CSharpCheck, CSharpTree> scanContext) {
        return new DetectionExecutive<>(tree, detectionRule, scanContext, this.handler);
    }

    @Nonnull
    @Override
    public IDetectionEngine<CSharpTree, CSharpSymbol> createDetectionEngineInstance(
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore) {
        return new CSharpDetectionEngine(detectionStore, this.handler);
    }

    @Nonnull
    @Override
    public IBaseMethodVisitorFactory<CSharpTree, CSharpSymbol> getBaseMethodVisitorFactory() {
        return CSharpBaseMethodVisitor::new;
    }

    @Nonnull
    @Override
    public Optional<CSharpTree> getEnclosingMethod(@Nonnull CSharpTree expression) {
        if (expression instanceof CSharpMethodInvocationTree invocation
                && invocation.getEnclosingBlock() != null) {
            return Optional.of(invocation.getEnclosingBlock());
        }
        if (expression instanceof CSharpObjectCreationTree creation
                && creation.getEnclosingBlock() != null) {
            return Optional.of(creation.getEnclosingBlock());
        }
        return Optional.empty();
    }

    @Nullable @Override
    public MethodMatcher<CSharpTree> createMethodMatcherBasedOn(
            @Nonnull CSharpTree methodDefinition) {
        // Inter-procedural method matching not supported without semantic analysis
        return null;
    }

    @Nullable @Override
    public EnumMatcher<CSharpTree> createSimpleEnumMatcherFor(
            @Nonnull CSharpTree enumIdentifier, @Nonnull MatchContext matchContext) {
        Optional<String> name = translation().getEnumIdentifierName(matchContext, enumIdentifier);
        return name.<EnumMatcher<CSharpTree>>map(EnumMatcher::new).orElse(null);
    }
}
