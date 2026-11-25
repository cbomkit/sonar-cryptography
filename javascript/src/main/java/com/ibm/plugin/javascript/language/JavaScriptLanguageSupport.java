/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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
import com.ibm.plugin.javascript.tree.JavaScriptCallTree;
import com.ibm.plugin.javascript.tree.JavaScriptTree;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Language support for JavaScript/TypeScript. Wires the translation, detection engine and base
 * method visitor into the shared {@link Handler} and {@link DetectionExecutive}, exactly as {@code
 * CSharpLanguageSupport} does.
 */
public final class JavaScriptLanguageSupport
        implements ILanguageSupport<
                JavaScriptCheck, JavaScriptTree, JavaScriptSymbol, JavaScriptScanContext> {

    @Nonnull
    private final Handler<JavaScriptCheck, JavaScriptTree, JavaScriptSymbol, JavaScriptScanContext>
            handler;

    @Nonnull private final JavaScriptLanguageTranslation translation;

    public JavaScriptLanguageSupport() {
        this.handler = new Handler<>(this);
        this.translation = new JavaScriptLanguageTranslation();
    }

    @Nonnull
    @Override
    public ILanguageTranslation<JavaScriptTree> translation() {
        return translation;
    }

    @Nonnull
    @Override
    public DetectionExecutive<
                    JavaScriptCheck, JavaScriptTree, JavaScriptSymbol, JavaScriptScanContext>
            createDetectionExecutive(
                    @Nonnull JavaScriptTree tree,
                    @Nonnull IDetectionRule<JavaScriptTree> detectionRule,
                    @Nonnull IScanContext<JavaScriptCheck, JavaScriptTree> scanContext) {
        return new DetectionExecutive<>(tree, detectionRule, scanContext, this.handler);
    }

    @Nonnull
    @Override
    public IDetectionEngine<JavaScriptTree, JavaScriptSymbol> createDetectionEngineInstance(
            @Nonnull
                    DetectionStore<
                                    JavaScriptCheck,
                                    JavaScriptTree,
                                    JavaScriptSymbol,
                                    JavaScriptScanContext>
                            detectionStore) {
        return new JavaScriptDetectionEngine(detectionStore, this.handler);
    }

    @Nonnull
    @Override
    public IBaseMethodVisitorFactory<JavaScriptTree, JavaScriptSymbol>
            getBaseMethodVisitorFactory() {
        return JavaScriptBaseMethodVisitor::new;
    }

    @Nonnull
    @Override
    public Optional<JavaScriptTree> getEnclosingMethod(@Nonnull JavaScriptTree expression) {
        if (expression instanceof JavaScriptCallTree call && call.getEnclosingBlock() != null) {
            return Optional.of(call.getEnclosingBlock());
        }
        return Optional.empty();
    }

    @Nullable @Override
    public MethodMatcher<JavaScriptTree> createMethodMatcherBasedOn(
            @Nonnull JavaScriptTree methodDefinition) {
        return null;
    }

    @Nullable @Override
    public EnumMatcher<JavaScriptTree> createSimpleEnumMatcherFor(
            @Nonnull JavaScriptTree enumIdentifier, @Nonnull MatchContext matchContext) {
        Optional<String> name = translation().getEnumIdentifierName(matchContext, enumIdentifier);
        return name.<EnumMatcher<JavaScriptTree>>map(EnumMatcher::new).orElse(null);
    }
}
