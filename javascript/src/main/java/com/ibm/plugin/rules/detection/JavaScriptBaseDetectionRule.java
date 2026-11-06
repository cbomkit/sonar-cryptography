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
package com.ibm.plugin.rules.detection;

import com.ibm.common.IObserver;
import com.ibm.engine.detection.Finding;
import com.ibm.engine.executive.DetectionExecutive;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.RuleSets;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.plugin.JavaScriptAggregator;
import com.ibm.plugin.javascript.language.JavaScriptCheck;
import com.ibm.plugin.javascript.language.JavaScriptScanContext;
import com.ibm.plugin.javascript.language.JavaScriptSymbol;
import com.ibm.plugin.javascript.tree.JavaScriptBlockTree;
import com.ibm.plugin.javascript.tree.JavaScriptTree;
import com.ibm.plugin.translation.JavaScriptTranslationProcess;
import com.ibm.plugin.translation.reorganizer.JavaScriptReorganizerRules;
import com.ibm.rules.IReportableDetectionRule;
import com.ibm.rules.issue.Issue;
import java.util.Collections;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Abstract base class for JavaScript/TypeScript cryptographic detection rules.
 *
 * <p>Runs every detection rule against every call in a block, one detection at a time (one {@code
 * DetectionStore} per call site, as for C#), and translates findings to {@link INode}s.
 */
public abstract class JavaScriptBaseDetectionRule
        implements JavaScriptCheck,
                IObserver<
                        Finding<
                                JavaScriptCheck,
                                JavaScriptTree,
                                JavaScriptSymbol,
                                JavaScriptScanContext>>,
                IReportableDetectionRule<JavaScriptTree> {

    private final boolean isInventory;
    @Nonnull protected final JavaScriptTranslationProcess javascriptTranslationProcess;
    @Nonnull protected final List<IDetectionRule<JavaScriptTree>> detectionRules;

    protected JavaScriptBaseDetectionRule() {
        this.isInventory = false;
        this.detectionRules = RuleSets.rulesOf(JavaScriptDetectionRules.class);
        this.javascriptTranslationProcess =
                new JavaScriptTranslationProcess(JavaScriptReorganizerRules.rules());
    }

    protected JavaScriptBaseDetectionRule(
            final boolean isInventory,
            @Nonnull List<IDetectionRule<JavaScriptTree>> detectionRules,
            @Nonnull List<IReorganizerRule> reorganizerRules) {
        this.isInventory = isInventory;
        this.detectionRules = detectionRules;
        this.javascriptTranslationProcess = new JavaScriptTranslationProcess(reorganizerRules);
    }

    @Override
    public void scan(
            @Nonnull JavaScriptScanContext scanContext, @Nonnull JavaScriptBlockTree blockTree) {
        for (JavaScriptTree statement : blockTree.getStatements()) {
            detectionRules.forEach(
                    rule -> {
                        DetectionExecutive<
                                        JavaScriptCheck,
                                        JavaScriptTree,
                                        JavaScriptSymbol,
                                        JavaScriptScanContext>
                                detectionExecutive =
                                        JavaScriptAggregator.getLanguageSupport()
                                                .createDetectionExecutive(
                                                        statement, rule, scanContext);
                        detectionExecutive.subscribe(this);
                        detectionExecutive.start();
                    });
        }
    }

    @Override
    public void update(
            @Nonnull
                    Finding<
                                    JavaScriptCheck,
                                    JavaScriptTree,
                                    JavaScriptSymbol,
                                    JavaScriptScanContext>
                            finding) {
        List<INode> nodes = javascriptTranslationProcess.initiate(finding.detectionStore());
        if (isInventory) {
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
    public List<Issue<JavaScriptTree>> report(
            @Nonnull JavaScriptTree markerTree, @Nonnull List<INode> translatedNodes) {
        return Collections.emptyList();
    }
}
