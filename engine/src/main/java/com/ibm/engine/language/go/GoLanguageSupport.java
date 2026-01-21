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
package com.ibm.engine.language.go;

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
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.sonar.plugins.go.api.Tree;
import org.sonar.plugins.go.api.checks.GoCheck;

/**
 * Language support implementation for Go. Provides the necessary infrastructure for cryptographic
 * detection in Go source code.
 */
public final class GoLanguageSupport
        implements ILanguageSupport<GoCheck, Tree, Void, GoScanContext> {

    @Nonnull private final Handler<GoCheck, Tree, Void, GoScanContext> handler;
    @Nonnull private final GoLanguageTranslation translation;

    public GoLanguageSupport() {
        this.handler = new Handler<>(this);
        this.translation = new GoLanguageTranslation();
    }

    @Nonnull
    @Override
    public ILanguageTranslation<Tree> translation() {
        return translation;
    }

    @Nonnull
    @Override
    public DetectionExecutive<GoCheck, Tree, Void, GoScanContext> createDetectionExecutive(
            @Nonnull Tree tree,
            @Nonnull IDetectionRule<Tree> detectionRule,
            @Nonnull IScanContext<GoCheck, Tree> scanContext) {
        return new DetectionExecutive<>(tree, detectionRule, scanContext, this.handler);
    }

    @Nonnull
    @Override
    public IDetectionEngine<Tree, Void> createDetectionEngineInstance(
            @Nonnull DetectionStore<GoCheck, Tree, Void, GoScanContext> detectionStore) {
        return new GoDetectionEngine(detectionStore, this.handler);
    }

    @Nonnull
    @Override
    public IBaseMethodVisitorFactory<Tree, Void> getBaseMethodVisitorFactory() {
        // Go uses a registration-based pattern rather than visitor pattern.
        // Return a no-op visitor factory since the Go plugin handles tree traversal
        // through its registration mechanism in GoCheck.initialize(InitContext).
        return (traceSymbol, detectionEngine) -> method -> {
            // No-op: Go detection is handled through the registration pattern
        };
    }

    @Nonnull
    @Override
    public Optional<Tree> getEnclosingMethod(@Nonnull Tree expression) {
        // Go API doesn't provide parent traversal through Tree nodes.
        // The Go plugin API doesn't expose a way to navigate up the AST.
        // For method scope tracking, we would need to track this during registration.
        return Optional.empty();
    }

    @Nullable
    @Override
    public MethodMatcher<Tree> createMethodMatcherBasedOn(@Nonnull Tree methodDefinition) {
        // Go function definitions in the current API don't provide enough
        // type information to create a reliable method matcher.
        // The Go plugin doesn't expose symbol information like Java does.
        return null;
    }

    @Nullable
    @Override
    public EnumMatcher<Tree> createSimpleEnumMatcherFor(
            @Nonnull Tree enumIdentifier, @Nonnull MatchContext matchContext) {
        // Go uses const blocks instead of enums.
        // The current API doesn't provide enum-like matching support.
        return null;
    }
}
