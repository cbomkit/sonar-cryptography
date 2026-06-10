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
import com.ibm.engine.language.cxx.CxxScanContext;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.plugin.CxxAggregator;
import com.ibm.plugin.translation.CxxTranslationProcess;
import com.ibm.plugin.translation.reorganizer.CxxReorganizerRules;
import com.ibm.rules.IReportableDetectionRule;
import com.ibm.rules.issue.Issue;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.AstNodeType;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.Collections;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.cxx.parser.CxxGrammarImpl;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.api.AstNodeTraversal;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;
import org.sonar.cxx.utils.CxxAstNodeHelper;

/**
 * Base class for C++ cryptography detection rules.
 *
 * <p>This class extends {@link SquidCheck} to integrate with the sonar-cxx analysis framework and
 * implements the observer pattern to receive detection findings from the engine.
 *
 * <p>The detection flow works as follows:
 *
 * <ol>
 *   <li>sonar-cxx calls {@link #visitFile(AstNode)} for each C++ file
 *   <li>We traverse the AST looking for function calls and constructor invocations
 *   <li>For each relevant node, we create a {@link DetectionExecutive} and start detection
 *   <li>When a finding is detected, {@link #update(Finding)} is called
 *   <li>The finding is translated, reorganized, enriched, and optionally reported
 * </ol>
 */
public abstract class CxxBaseDetectionRule extends SquidCheck<Grammar>
        implements IObserver<
                        Finding<
                                SquidCheck<?>,
                                AstNode,
                                Symbol,
                                SquidAstVisitorContext<? extends Grammar>>>,
                IReportableDetectionRule<AstNode> {

    /** Node types to detect: function calls, new expressions, and enum specifiers. */
    private static final AstNodeType[] DETECTION_NODE_TYPES = {
        CxxGrammarImpl.postfixExpression, CxxGrammarImpl.newExpression, CxxGrammarImpl.enumSpecifier
    };

    private final boolean isInventory;
    @Nonnull protected final CxxTranslationProcess cxxTranslationProcess;
    @Nonnull protected final List<IDetectionRule<AstNode>> detectionRules;

    protected CxxBaseDetectionRule() {
        this.isInventory = false;
        this.detectionRules = CxxDetectionRules.rules();
        this.cxxTranslationProcess = new CxxTranslationProcess(CxxReorganizerRules.rules());
    }

    protected CxxBaseDetectionRule(
            final boolean isInventory,
            @Nonnull List<IDetectionRule<AstNode>> detectionRules,
            @Nonnull List<IReorganizerRule> reorganizerRules) {
        this.isInventory = isInventory;
        this.detectionRules = detectionRules;
        this.cxxTranslationProcess = new CxxTranslationProcess(reorganizerRules);
    }

    /**
     * Called when visiting a file. Traverses the AST to find detection targets.
     *
     * @param astNode The root AST node of the file
     */
    @Override
    public void visitFile(@Nonnull AstNode astNode) {
        // Traverse the entire AST looking for function calls, new expressions, and enums
        AstNodeTraversal.traverse(astNode, DETECTION_NODE_TYPES, this::processNode);
    }

    /**
     * Processes a single AST node for potential cryptographic detection.
     *
     * @param node The AST node to process
     */
    private void processNode(@Nonnull AstNode node) {
        // Only process actual function calls and constructor calls, not all postfix expressions
        if (node.is(CxxGrammarImpl.postfixExpression)) {
            if (!CxxAstNodeHelper.isFunctionCall(node)
                    && !CxxAstNodeHelper.isConstructorCall(node)) {
                return;
            }
        }

        detectionRules.forEach(
                rule -> {
                    DetectionExecutive<
                                    SquidCheck<?>,
                                    AstNode,
                                    Symbol,
                                    SquidAstVisitorContext<? extends Grammar>>
                            detectionExecutive =
                                    CxxAggregator.getLanguageSupport()
                                            .createDetectionExecutive(
                                                    node,
                                                    rule,
                                                    new CxxScanContext(this.getContext()));
                    detectionExecutive.subscribe(this);
                    detectionExecutive.start();
                });
    }

    /**
     * Called when a finding is detected by the engine.
     *
     * @param finding A finding containing detection store information.
     */
    @Override
    public void update(
            @Nonnull
                    Finding<
                                    SquidCheck<?>,
                                    AstNode,
                                    Symbol,
                                    SquidAstVisitorContext<? extends Grammar>>
                            finding) {
        final List<INode> nodes = cxxTranslationProcess.initiate(finding.detectionStore());
        if (isInventory) {
            CxxAggregator.addNodes(nodes);
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
    @Nonnull
    public List<Issue<AstNode>> report(
            @Nonnull AstNode markerTree, @Nonnull List<INode> translatedNodes) {
        // override by higher level rule, to report an issue
        return Collections.emptyList();
    }
}
