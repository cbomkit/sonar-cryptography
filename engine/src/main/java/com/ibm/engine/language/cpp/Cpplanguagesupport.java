/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2025 PQCA
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
package com.ibm.engine.language.cpp;

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
import com.ibm.engine.language.cpp.tree.CppMethodInvocationTree;
import com.ibm.engine.language.cpp.tree.CppTree;
import com.ibm.engine.rule.IDetectionRule;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Language support implementation for C/C++.
 *
 * <p>Mirrors {@link com.ibm.engine.language.csharp.CSharpLanguageSupport}: wires together the
 * {@link CppLanguageTranslation}, {@link CppDetectionEngine}, and {@link CppBaseMethodVisitor}
 * using the shared {@link Handler} and {@link DetectionExecutive} infrastructure.
 *
 * <p>This is the top-level factory that the rest of the plugin uses for C/C++ scanning. It is
 * registered in {@link com.ibm.engine.language.LanguageSupporter#cppLanguageSupporter()}.
 */
public final class CppLanguageSupport
        implements ILanguageSupport<CppCheck, CppTree, CppSymbol, CppScanContext> {

    @Nonnull
    private final Handler<CppCheck, CppTree, CppSymbol, CppScanContext> handler;

    @Nonnull
    private final CppLanguageTranslation translation;

    public CppLanguageSupport() {
        this.handler = new Handler<>(this);
        this.translation = new CppLanguageTranslation();
    }

    @Nonnull
    @Override
    public ILanguageTranslation<CppTree> translation() {
        return translation;
    }

    @Nonnull
    @Override
    public DetectionExecutive<CppCheck, CppTree, CppSymbol, CppScanContext>
            createDetectionExecutive(
                    @Nonnull CppTree tree,
                    @Nonnull IDetectionRule<CppTree> detectionRule,
                    @Nonnull IScanContext<CppCheck, CppTree> scanContext) {
        return new DetectionExecutive<>(tree, detectionRule, scanContext, this.handler);
    }

    @Nonnull
    @Override
    public IDetectionEngine<CppTree, CppSymbol> createDetectionEngineInstance(
            @Nonnull DetectionStore<CppCheck, CppTree, CppSymbol, CppScanContext> detectionStore) {
        return new CppDetectionEngine(detectionStore, this.handler);
    }

    @Nonnull
    @Override
    public IBaseMethodVisitorFactory<CppTree, CppSymbol> getBaseMethodVisitorFactory() {
        return CppBaseMethodVisitor::new;
    }

    @Nonnull
    @Override
    public Optional<CppTree> getEnclosingMethod(@Nonnull CppTree expression) {
        if (expression instanceof CppMethodInvocationTree invocation
                && invocation.enclosingBlock() != null) {
            return Optional.of(invocation.enclosingBlock());
        }
        return Optional.empty();
    }

    @Nullable
    @Override
    public MethodMatcher<CppTree> createMethodMatcherBasedOn(
            @Nonnull CppTree methodDefinition) {
        // Inter-procedural method matching not supported without semantic analysis
        return null;
    }

    @Nullable
    @Override
    public EnumMatcher<CppTree> createSimpleEnumMatcherFor(
            @Nonnull CppTree enumIdentifier, @Nonnull MatchContext matchContext) {
        Optional<String> name = translation().getEnumIdentifierName(matchContext, enumIdentifier);
        return name.<EnumMatcher<CppTree>>map(EnumMatcher::new).orElse(null);
    }
}
