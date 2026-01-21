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
import org.sonar.go.symbols.Symbol;
import org.sonar.plugins.go.api.FunctionDeclarationTree;
import org.sonar.plugins.go.api.IdentifierTree;
import org.sonar.plugins.go.api.Tree;
import org.sonar.plugins.go.api.checks.GoCheck;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

import static com.ibm.engine.detection.MethodMatcher.ANY;

/**
 * Language support implementation for Go. Provides the necessary infrastructure for cryptographic
 * detection in Go source code.
 */
public final class GoLanguageSupport
        implements ILanguageSupport<GoCheck, Tree, Symbol, GoScanContext> {

    @Nonnull private final Handler<GoCheck, Tree, Symbol, GoScanContext> handler;
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
    public DetectionExecutive<GoCheck, Tree, Symbol, GoScanContext> createDetectionExecutive(
            @Nonnull Tree tree,
            @Nonnull IDetectionRule<Tree> detectionRule,
            @Nonnull IScanContext<GoCheck, Tree> scanContext) {
        return new DetectionExecutive<>(tree, detectionRule, scanContext, this.handler);
    }

    @Nonnull
    @Override
    public IDetectionEngine<Tree, Symbol> createDetectionEngineInstance(
            @Nonnull DetectionStore<GoCheck, Tree, Symbol, GoScanContext> detectionStore) {
        return new GoDetectionEngine(detectionStore, this.handler);
    }

    @Nonnull
    @Override
    public IBaseMethodVisitorFactory<Tree, Symbol> getBaseMethodVisitorFactory() {
        return GoBaseMethodVisitor::new;
    }

    @Nonnull
    @Override
    public Optional<Tree> getEnclosingMethod(@Nonnull Tree expression) {
        // Navigate up the tree to find the enclosing FunctionDeclarationTree
        // Go Tree API provides children() but not parent(), so we need to track context
        // during registration. For now, check if expression itself is a function declaration.
        if (expression instanceof FunctionInvocationWIthIdentifiersTree functionInvocationWIthIdentifiersTree) {
            return Optional.of(functionInvocationWIthIdentifiersTree.getBlockTree());
        }
        // Without parent() access, we cannot navigate up. The Go plugin handles this
        // through its registration pattern - handlers are registered for specific tree types.
        return Optional.empty();
    }

    @Nullable @Override
    public MethodMatcher<Tree> createMethodMatcherBasedOn(@Nonnull Tree methodDefinition) {
        if (methodDefinition instanceof FunctionDeclarationTree functionDecl) {
            // Get the function name
            IdentifierTree nameTree = functionDecl.name();
            if (nameTree == null) {
                return null;
            }
            String functionName = nameTree.name();

            // Get the invocation object name (package or receiver type)
            String invocationObjectName = "";
            String receiverType = functionDecl.receiverType();
            if (receiverType != null && !receiverType.isEmpty()) {
                // Method with receiver: type.Method()
                invocationObjectName = receiverType;
            } else {
                // Package-level function: package.Function()
                String packageName = nameTree.packageName();
                if (packageName != null && !packageName.isEmpty()) {
                    invocationObjectName = packageName;
                }
            }

            // Get parameter types (Go is dynamically typed at the API level, so use ANY)
            List<Tree> formalParameters = functionDecl.formalParameters();
            LinkedList<String> parameterTypeList = new LinkedList<>();
            if (formalParameters != null) {
                String[] parameters =
                        formalParameters.stream().map(param -> ANY).toArray(String[]::new);
                parameterTypeList = new LinkedList<>(Arrays.asList(parameters));
            }

            return new MethodMatcher<>(invocationObjectName, functionName, parameterTypeList);
        }
        return null;
    }

    @Nullable @Override
    public EnumMatcher<Tree> createSimpleEnumMatcherFor(
            @Nonnull Tree enumIdentifier, @Nonnull MatchContext matchContext) {
        // Go uses const blocks instead of enums.
        Optional<String> enumIdentifierName =
                translation().getEnumIdentifierName(matchContext, enumIdentifier);
        return enumIdentifierName.<EnumMatcher<Tree>>map(EnumMatcher::new).orElse(null);
    }
}
