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
import com.ibm.engine.language.csharp.CSharpCheck;
import com.ibm.engine.language.csharp.CSharpScanContext;
import com.ibm.engine.language.csharp.CSharpSymbol;
import com.ibm.engine.language.csharp.tree.CSharpBlockTree;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.plugin.CSharpAggregator;
import com.ibm.plugin.translation.CSharpTranslationProcess;
import com.ibm.plugin.translation.reorganizer.CSharpReorganizerRules;
import com.ibm.rules.IReportableDetectionRule;
import com.ibm.rules.issue.Issue;
import java.util.Collections;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Abstract base class for C# cryptographic detection rules.
 *
 * <p>Mirrors {@code GoBaseDetectionRule}: holds a set of {@link IDetectionRule}s, runs them for
 * every method body via {@link CSharpCheck#scan}, and translates findings to {@link INode} objects.
 */
public abstract class CSharpBaseDetectionRule
        implements CSharpCheck,
                IObserver<Finding<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>>,
                IReportableDetectionRule<CSharpTree> {

    private final boolean isInventory;
    @Nonnull protected final CSharpTranslationProcess csharpTranslationProcess;
    @Nonnull protected final List<IDetectionRule<CSharpTree>> detectionRules;

    protected CSharpBaseDetectionRule() {
        this.isInventory = false;
        this.detectionRules = CSharpDetectionRules.rules();
        this.csharpTranslationProcess =
                new CSharpTranslationProcess(CSharpReorganizerRules.rules());
    }

    protected CSharpBaseDetectionRule(
            final boolean isInventory,
            @Nonnull List<IDetectionRule<CSharpTree>> detectionRules,
            @Nonnull List<IReorganizerRule> reorganizerRules) {
        this.isInventory = isInventory;
        this.detectionRules = detectionRules;
        this.csharpTranslationProcess = new CSharpTranslationProcess(reorganizerRules);
    }

    @Override
    public void scan(@Nonnull CSharpScanContext scanContext, @Nonnull CSharpBlockTree blockTree) {
        detectionRules.forEach(
                rule -> {
                    DetectionExecutive<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionExecutive =
                                    CSharpAggregator.getLanguageSupport()
                                            .createDetectionExecutive(blockTree, rule, scanContext);
                    detectionExecutive.subscribe(this);
                    detectionExecutive.start();
                });
    }

    @Override
    public void update(
            @Nonnull Finding<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> finding) {
        List<INode> nodes = csharpTranslationProcess.initiate(finding.detectionStore());
        if (isInventory) {
            CSharpAggregator.addNodes(nodes);
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
    public List<Issue<CSharpTree>> report(
            @Nonnull CSharpTree markerTree, @Nonnull List<INode> translatedNodes) {
        return Collections.emptyList();
    }
}
