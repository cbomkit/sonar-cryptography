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
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.plugin.JavaScriptAggregator;
import com.ibm.plugin.javascript.api.BlockTree;
import com.ibm.plugin.javascript.api.JavaScriptCheck;
import com.ibm.plugin.javascript.api.JavaScriptSymbol;
import com.ibm.plugin.javascript.api.Tree;
import com.ibm.plugin.javascript.language.JavaScriptScanContext;
import com.ibm.plugin.translation.JavaScriptTranslationProcess;
import com.ibm.plugin.translation.reorganizer.JavaScriptReorganizerRules;
import com.ibm.rules.IReportableDetectionRule;
import com.ibm.rules.issue.Issue;
import java.util.Collections;
import java.util.List;
import javax.annotation.Nonnull;

/** Base detection rule for JavaScript/Node.js cryptographic patterns. */
public abstract class JavaScriptBaseDetectionRule
        implements JavaScriptCheck,
                IObserver<Finding<JavaScriptCheck, Tree, JavaScriptSymbol, JavaScriptScanContext>>,
                IReportableDetectionRule<Tree> {

    private final boolean isInventory;
    @Nonnull protected final JavaScriptTranslationProcess javascriptTranslationProcess;
    @Nonnull protected final List<IDetectionRule<Tree>> detectionRules;

    protected JavaScriptBaseDetectionRule() {
        this.isInventory = false;
        this.detectionRules = JavaScriptDetectionRules.rules();
        this.javascriptTranslationProcess =
                new JavaScriptTranslationProcess(JavaScriptReorganizerRules.rules());
    }

    protected JavaScriptBaseDetectionRule(
            final boolean isInventory,
            @Nonnull List<IDetectionRule<Tree>> detectionRules,
            @Nonnull List<IReorganizerRule> reorganizerRules) {
        this.isInventory = isInventory;
        this.detectionRules = detectionRules;
        this.javascriptTranslationProcess = new JavaScriptTranslationProcess(reorganizerRules);
    }

    /** Runs all detection rules against the parsed file block tree. */
    public void analyzeBlock(
            @Nonnull BlockTree blockTree, @Nonnull JavaScriptScanContext scanContext) {
        detectionRules.forEach(
                rule -> {
                    DetectionExecutive<
                                    JavaScriptCheck, Tree, JavaScriptSymbol, JavaScriptScanContext>
                            detectionExecutive =
                                    JavaScriptAggregator.getLanguageSupport()
                                            .createDetectionExecutive(blockTree, rule, scanContext);
                    detectionExecutive.subscribe(finding -> this.update(finding));
                    detectionExecutive.start();
                });
    }

    @Override
    public void update(
            @Nonnull
                    Finding<JavaScriptCheck, Tree, JavaScriptSymbol, JavaScriptScanContext>
                            finding) {
        List<INode> nodes = javascriptTranslationProcess.initiate(finding.detectionStore());
        if (isInventory && !nodes.isEmpty()) {
            JavaScriptAggregator.addNodes(nodes);
        }
        this.report(finding.getMarkerTree(), nodes)
                .forEach(
                        issue ->
                                finding.detectionStore()
                                        .getScanContext()
                                        .reportIssue(this, issue.tree(), issue.message()));
    }

    @Override
    @Nonnull
    public List<Issue<Tree>> report(
            @Nonnull Tree markerTree, @Nonnull List<INode> translatedNodes) {
        return Collections.emptyList();
    }
}
