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
import com.ibm.plugin.javascript.api.BlockTree;
import com.ibm.plugin.javascript.api.CallExpressionWithBlockTree;
import com.ibm.plugin.javascript.api.IdentifierWithBlockTree;
import com.ibm.plugin.javascript.api.JavaScriptCheck;
import com.ibm.plugin.javascript.api.JavaScriptSymbol;
import com.ibm.plugin.javascript.api.Tree;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/** Language support implementation for JavaScript/TypeScript via the ESLint bridge. */
public final class JavaScriptLanguageSupport
        implements ILanguageSupport<
                JavaScriptCheck, Tree, JavaScriptSymbol, JavaScriptScanContext> {

    @Nonnull
    private final Handler<JavaScriptCheck, Tree, JavaScriptSymbol, JavaScriptScanContext> handler;

    @Nonnull private final JavaScriptLanguageTranslation translation;

    public JavaScriptLanguageSupport() {
        this.handler = new Handler<>(this);
        this.translation = new JavaScriptLanguageTranslation();
    }

    @Nonnull
    @Override
    public ILanguageTranslation<Tree> translation() {
        return translation;
    }

    @Nonnull
    @Override
    public DetectionExecutive<JavaScriptCheck, Tree, JavaScriptSymbol, JavaScriptScanContext>
            createDetectionExecutive(
                    @Nonnull Tree tree,
                    @Nonnull IDetectionRule<Tree> detectionRule,
                    @Nonnull IScanContext<JavaScriptCheck, Tree> scanContext) {
        return new DetectionExecutive<>(tree, detectionRule, scanContext, handler);
    }

    @Nonnull
    @Override
    public IDetectionEngine<Tree, JavaScriptSymbol> createDetectionEngineInstance(
            @Nonnull
                    DetectionStore<JavaScriptCheck, Tree, JavaScriptSymbol, JavaScriptScanContext>
                            detectionStore) {
        return new JavaScriptDetectionEngine(detectionStore, handler);
    }

    @Nonnull
    @Override
    public IBaseMethodVisitorFactory<Tree, JavaScriptSymbol> getBaseMethodVisitorFactory() {
        return JavaScriptBaseMethodVisitor::new;
    }

    @Nonnull
    @Override
    public Optional<Tree> getEnclosingMethod(@Nonnull Tree expression) {
        if (expression instanceof BlockTree blockTree) {
            return Optional.of(blockTree);
        }
        if (expression instanceof CallExpressionWithBlockTree wrapped) {
            return Optional.of(wrapped.blockTree());
        }
        if (expression instanceof IdentifierWithBlockTree identifierWithBlock) {
            return Optional.of(identifierWithBlock.blockTree());
        }
        return Optional.empty();
    }

    @Nullable @Override
    public MethodMatcher<Tree> createMethodMatcherBasedOn(@Nonnull Tree methodDefinition) {
        return null;
    }

    @Nullable @Override
    public EnumMatcher<Tree> createSimpleEnumMatcherFor(
            @Nonnull Tree enumIdentifier, @Nonnull MatchContext matchContext) {
        Optional<String> name = translation.getEnumIdentifierName(matchContext, enumIdentifier);
        return name.<EnumMatcher<Tree>>map(EnumMatcher::new).orElse(null);
    }
}
