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
package com.ibm.plugin.rules.detection;

import com.ibm.common.IObserver;
import com.ibm.engine.detection.Finding;
import com.ibm.engine.executive.DetectionExecutive;
import com.ibm.engine.language.java.JavaScanContext;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.plugin.JavaAggregator;
import com.ibm.plugin.JavaScanMemoryLogger;
import com.ibm.plugin.translation.JavaTranslationProcess;
import com.ibm.plugin.translation.reorganizer.JavaReorganizerRules;
import com.ibm.rules.IReportableDetectionRule;
import com.ibm.rules.issue.Issue;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.annotation.Nonnull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.plugins.java.api.IssuableSubscriptionVisitor;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

public abstract class JavaBaseDetectionRule extends IssuableSubscriptionVisitor
        implements IObserver<Finding<JavaCheck, Tree, Symbol, JavaFileScannerContext>>,
                IReportableDetectionRule<Tree> {
    private static final Logger LOGGER = LoggerFactory.getLogger(JavaBaseDetectionRule.class);
    private static final long FILE_PROGRESS_LOG_EVERY = 2500L;

    private final boolean isInventory;

    @Nonnull
    private final List<DetectionExecutive<JavaCheck, Tree, Symbol, JavaFileScannerContext>>
            deferredDetectionExecutives = new ArrayList<>();

    @Nonnull protected final JavaTranslationProcess javaTranslationProcess;
    @Nonnull protected final List<IDetectionRule<Tree>> detectionRules;

    protected JavaBaseDetectionRule() {
        this.isInventory = false;
        this.detectionRules = JavaDetectionRules.rules();
        this.javaTranslationProcess = new JavaTranslationProcess(JavaReorganizerRules.rules());
    }

    protected JavaBaseDetectionRule(
            final boolean isInventory,
            @Nonnull List<IDetectionRule<Tree>> detectionRules,
            @Nonnull List<IReorganizerRule> reorganizerRules) {
        this.isInventory = isInventory;
        this.detectionRules = detectionRules;
        this.javaTranslationProcess = new JavaTranslationProcess(reorganizerRules);
    }

    /**
     * Returns a list of tree nodes to visit during detection.
     *
     * @return A list of tree node kinds to visit.
     */
    @Override
    public List<Tree.Kind> nodesToVisit() {
        return List.of(Tree.Kind.METHOD_INVOCATION, Tree.Kind.NEW_CLASS, Tree.Kind.ENUM);
    }

    /**
     * When a file finishes analysis, detach its still-retained recorded calls so the file's AST
     * becomes garbage-collectable. Same-file detections have already fired with the live context.
     *
     * @param context the scanner context of the file that finished analysis
     */
    @Override
    public void leaveFile(@Nonnull JavaFileScannerContext context) {
        JavaAggregator.getLanguageSupport().notifyLeaveFile(context.getInputFile());
    }

    /**
     * Visits a tree node and applies detection rules to it.
     *
     * @param tree The tree node to visit.
     */
    @Override
    public void visitNode(@Nonnull Tree tree) {
        detectionRules.forEach(
                rule -> {
                    DetectionExecutive<JavaCheck, Tree, Symbol, JavaFileScannerContext>
                            detectionExecutive =
                                    JavaAggregator.getLanguageSupport()
                                            .createDetectionExecutive(
                                                    tree, rule, new JavaScanContext(this.context));
                    detectionExecutive.subscribe(this);
                    detectionExecutive.start();
                    if (detectionExecutive.hasDeferredHooks() && !detectionExecutive.isReleased()) {
                        deferredDetectionExecutives.add(detectionExecutive);
                    }
                });
    }

    /**
     * On new finding.
     *
     * @param finding A finding containing detection store information.
     */
    @Override
    public void update(@Nonnull Finding<JavaCheck, Tree, Symbol, JavaFileScannerContext> finding) {
        final List<INode> nodes = javaTranslationProcess.initiate(finding.detectionStore());
        if (isInventory) {
            JavaAggregator.addNodes(nodes);
        }
        // report
        this.report(finding.getMarkerTree(), nodes)
                .forEach(
                        issue ->
                                finding.detectionStore()
                                        .getScanContext()
                                        .reportIssue(this, issue.tree(), issue.message()));
    }

    @Override
    public void leaveFile(@Nonnull JavaFileScannerContext context) {
        try {
            super.leaveFile(context);
        } finally {
            releaseDeferredExecutives();
            JavaAggregator.resetLanguageSupport();
            if (isInventory) {
                JavaScanMemoryLogger.logFileProgress(LOGGER, FILE_PROGRESS_LOG_EVERY);
            }
        }
    }

    @Override
    @Nonnull
    public List<Issue<Tree>> report(
            @Nonnull Tree markerTree, @Nonnull List<INode> translatedNodes) {
        // override by higher level rule, to report an issue
        return Collections.emptyList();
    }

    private void releaseDeferredExecutives() {
        deferredDetectionExecutives.forEach(DetectionExecutive::releaseDeferredResources);
        deferredDetectionExecutives.clear();
    }
}
