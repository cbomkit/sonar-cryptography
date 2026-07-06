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
package com.ibm.engine.language.java;

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
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.java.model.ExpressionUtils;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.BaseTreeVisitor;
import org.sonar.plugins.java.api.tree.ClassTree;
import org.sonar.plugins.java.api.tree.ExpressionTree;
import org.sonar.plugins.java.api.tree.MethodInvocationTree;
import org.sonar.plugins.java.api.tree.MethodTree;
import org.sonar.plugins.java.api.tree.NewArrayTree;
import org.sonar.plugins.java.api.tree.Tree;
import org.sonar.plugins.java.api.tree.TypeTree;
import org.sonar.plugins.java.api.tree.VariableTree;

public final class JavaLanguageSupport
        implements ILanguageSupport<JavaCheck, Tree, Symbol, JavaFileScannerContext> {
    private static final Logger LOGGER = LoggerFactory.getLogger(JavaLanguageSupport.class);
    @Nonnull private final Handler<JavaCheck, Tree, Symbol, JavaFileScannerContext> handler;

    public JavaLanguageSupport() {
        this.handler = new Handler<>(this);
    }

    @Nonnull
    @Override
    public ILanguageTranslation<Tree> translation() {
        return new JavaLanguageTranslation();
    }

    @Nonnull
    @Override
    public DetectionExecutive<JavaCheck, Tree, Symbol, JavaFileScannerContext>
            createDetectionExecutive(
                    @Nonnull Tree tree,
                    @Nonnull IDetectionRule<Tree> detectionRule,
                    @Nonnull IScanContext<JavaCheck, Tree> scanContext) {
        return new DetectionExecutive<>(tree, detectionRule, scanContext, this.handler);
    }

    @Nonnull
    @Override
    public IDetectionEngine<Tree, Symbol> createDetectionEngineInstance(
            @Nonnull
                    DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext>
                            detectionStore) {
        return new JavaDetectionEngine(detectionStore, this.handler);
    }

    @Nonnull
    @Override
    public IBaseMethodVisitorFactory<Tree, Symbol> getBaseMethodVisitorFactory() {
        return JavaBaseMethodVisitor::new;
    }

    @Nonnull
    @Override
    public Optional<Tree> getEnclosingMethod(@Nonnull Tree expression) {
        if (expression instanceof ExpressionTree expressionTree) {
            return Optional.ofNullable(ExpressionUtils.getEnclosingMethod(expressionTree));
        }
        return Optional.empty();
    }

    @Nullable @Override
    public MethodMatcher<Tree> createMethodMatcherBasedOn(@Nonnull Tree methodDefinition) {
        if (methodDefinition instanceof MethodTree method) {
            Symbol.TypeSymbol enclosingClass = method.symbol().enclosingClass();
            if (enclosingClass == null) {
                return null;
            }
            ClassTree classDeclaration = enclosingClass.declaration();
            if (classDeclaration == null) {
                return null;
            }
            String invocationObjectName = classDeclaration.symbol().type().fullyQualifiedName();

            try {
                TypeTree returnType = method.returnType();
                if (returnType == null) {
                    return null;
                }
                String name = method.simpleName().name();
                String[] parameters =
                        method.parameters().stream()
                                .map(para -> para.type().symbolType().fullyQualifiedName())
                                .toArray(String[]::new);
                LinkedList<String> parameterTypeList = new LinkedList<>(Arrays.asList(parameters));

                return new MethodMatcher<>(invocationObjectName, name, parameterTypeList);
            } catch (Exception e) {
                LOGGER.error(e.getLocalizedMessage());
                return null;
            }
        }
        return null;
    }

    @Nullable @Override
    public EnumMatcher<Tree> createSimpleEnumMatcherFor(
            @Nonnull Tree enumIdentifier, @Nonnull MatchContext matchContext) {
        Optional<String> enumIdentifierName =
                translation().getEnumIdentifierName(matchContext, enumIdentifier);
        return enumIdentifierName.<EnumMatcher<Tree>>map(EnumMatcher::new).orElse(null);
    }

    @Override
    public void notifyLeaveFile(@Nonnull org.sonar.api.batch.fs.InputFile inputFile) {
        this.handler.detachCallsForFile(inputFile);
    }

    @Override
    @Nonnull
    public CallContextStats callContextStats() {
        return this.handler.callContextStats();
    }

    @Override
    public boolean isDetachableCall(@Nonnull Tree tree) {
        if (!(tree instanceof MethodInvocationTree invocation)) {
            // Enum accesses and other kinds stay retained in this iteration.
            return false;
        }
        // NB: we deliberately do NOT require methodSymbol().declaration() != null. Cross-file calls
        // resolve their callee via the compiled classpath (sonar.java.binaries), so declaration()
        // is
        // null for exactly the cross-file calls that drive the heap retention. Detachability
        // depends
        // on argument pre-resolvability (checked when building the record, with a retained-tree
        // fallback) and on matchKeys (record-time type/name/params), neither of which needs the
        // callee's source declaration.
        for (ExpressionTree argument : invocation.arguments()) {
            if (containsNewArray(argument)) {
                // NEW_ARRAY resolution is value-factory dependent (SizeFactory returns the array
                // size, otherwise its elements). We cannot reproduce that generically at record
                // time, so keep such calls on the retained-tree fallback path.
                return false;
            }
        }
        return true;
    }

    @Override
    public int parameterIndexOf(@Nonnull Tree methodDefinition, @Nonnull Tree methodParameter) {
        if (!(methodDefinition instanceof MethodTree method)) {
            return -1;
        }
        final Optional<String> targetName =
                translation()
                        .resolveIdentifierAsString(
                                MatchContext.createForHookContext(), methodParameter);
        if (targetName.isEmpty()) {
            return -1;
        }
        final List<VariableTree> parameters = method.parameters();
        for (int i = 0; i < parameters.size(); i++) {
            if (parameters.get(i).simpleName().name().equals(targetName.get())) {
                return i;
            }
        }
        return -1;
    }

    private static boolean containsNewArray(@Nonnull Tree tree) {
        final boolean[] found = {false};
        tree.accept(
                new BaseTreeVisitor() {
                    @Override
                    public void visitNewArray(NewArrayTree newArrayTree) {
                        found[0] = true;
                    }
                });
        return found[0];
    }
}
