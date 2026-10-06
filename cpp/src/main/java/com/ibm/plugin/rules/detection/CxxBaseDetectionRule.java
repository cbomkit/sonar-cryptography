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
import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.detection.Finding;
import com.ibm.engine.executive.DetectionExecutive;
import com.ibm.engine.language.cxx.CxxConstructorCalls;
import com.ibm.engine.language.cxx.CxxScanContext;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.mapper.model.IAsset;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.collections.IAssetCollection;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.plugin.CxxAggregator;
import com.ibm.plugin.translation.CxxTranslationProcess;
import com.ibm.plugin.translation.reorganizer.CxxReorganizerRules;
import com.ibm.rules.IReportableDetectionRule;
import com.ibm.rules.issue.Issue;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.AstNodeType;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.IntStream;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.cxx.parser.CxxGrammarImpl;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.api.AstNodeSymbolExtension;
import org.sonar.cxx.squidbridge.api.AstNodeTraversal;
import org.sonar.cxx.squidbridge.api.AstNodeTypeExtension;
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
 *   <li>sonar-cxx finishes its shared node-by-node walk of the file (symbol resolution included)
 *       and calls {@link #leaveFile(AstNode)}
 *   <li>We traverse the AST looking for function calls and constructor invocations
 *   <li>For each relevant node, we create a {@link DetectionExecutive} and start detection
 *   <li>When a finding is detected, {@link #update(Finding)} collects it
 *   <li>Once the file is traversed, each finding that no other finding reports (see {@link
 *       #leaveFile}) is translated, reorganized, enriched, and optionally reported
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

    private static final Logger LOGGER = LoggerFactory.getLogger(CxxBaseDetectionRule.class);

    /** Node types to detect: function calls, new expressions, and enum specifiers. */
    private static final AstNodeType[] DETECTION_NODE_TYPES = {
        CxxGrammarImpl.postfixExpression,
        CxxGrammarImpl.newExpression,
        CxxGrammarImpl.initDeclarator,
        CxxGrammarImpl.enumSpecifier
    };

    private final boolean isInventory;
    @Nonnull protected final CxxTranslationProcess cxxTranslationProcess;
    @Nonnull protected final List<IDetectionRule<AstNode>> detectionRules;

    /** The findings of the file, handled once the file is traversed, see {@link #leaveFile}. */
    @Nonnull
    private final List<
                    Finding<
                            SquidCheck<?>,
                            AstNode,
                            Symbol,
                            SquidAstVisitorContext<? extends Grammar>>>
            fileFindings = new ArrayList<>();

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

    @Override
    public void init() {
        CxxSymbolExtensionRelease.register(getContext(), this);
    }

    /**
     * Called when a file finishes analysis. Traverses the AST to find detection targets.
     *
     * <p>{@code leaveFile} runs after sonar-cxx's shared node-by-node walk of the file, over every
     * registered visitor - including {@code CxxSymbolResolverVisitor}, which populates {@link
     * AstNodeSymbolExtension}/{@link AstNodeTypeExtension} during that walk - so symbol resolution
     * for the whole file is already complete by the time this runs. The file's symbol and type
     * entries are removed by {@link CxxSymbolExtensionRelease} once every rule of the scan has left
     * the file.
     *
     * <p>A call can be detected on its own and also be reported by the finding of another call,
     * e.g. {@code EVP_aes_256_gcm()} passed to {@code EVP_EncryptInit_ex}, a cipher fetched into a
     * variable that is passed to it, or {@code EVP_EncryptInit_ex} made on a context created by
     * {@code EVP_CIPHER_CTX_new()}. The findings of the file are therefore collected first, and a
     * finding is handled only if its call is not reported by another finding of the file, and if it
     * describes a cryptographic asset.
     *
     * @param astNode the root AST node of the file that finished analysis, or {@code null} on a
     *     parse error
     */
    @Override
    public void leaveFile(@Nullable AstNode astNode) {
        try {
            if (astNode != null) {
                detectIn(astNode);
            }
        } catch (RuntimeException e) {
            // the other files of the scan are analyzed regardless, as sonar-java and the Go
            // sensor do for a file whose analysis fails
            LOGGER.error(
                    "Unable to detect cryptographic assets in file '{}'",
                    getContext().getInputFile(),
                    e);
        } finally {
            fileFindings.clear();
            if (astNode != null) {
                CxxSymbolExtensionRelease.leaveFile(getContext(), this, astNode);
            }
            CxxAggregator.getLanguageSupport().notifyLeaveFile(getContext().getInputFile());
        }
    }

    /** Detects, translates and reports the findings of the file rooted at {@code astNode}. */
    private void detectIn(@Nonnull AstNode astNode) {
        fileFindings.clear();
        AstNodeTraversal.traverse(astNode, DETECTION_NODE_TYPES, this::processNode);
        final List<
                        Finding<
                                SquidCheck<?>,
                                AstNode,
                                Symbol,
                                SquidAstVisitorContext<? extends Grammar>>>
                findings = List.copyOf(fileFindings);
        fileFindings.clear();
        for (Finding<SquidCheck<?>, AstNode, Symbol, SquidAstVisitorContext<? extends Grammar>>
                finding : withoutFindingsReportedByOthers(findings)) {
            final List<INode> nodes = cxxTranslationProcess.initiate(finding.detectionStore());
            // an operation whose algorithm is not known, e.g. the key set on a cipher context
            // initialized elsewhere, describes no cryptographic asset
            if (describesAnAsset(nodes)) {
                onFinding(finding, nodes);
            }
        }
    }

    /**
     * Processes a single AST node for potential cryptographic detection.
     *
     * @param node The AST node to process
     */
    private void processNode(@Nonnull AstNode node) {
        // Only process actual function calls and constructor calls, not all postfix expressions
        // and declarations
        if (node.is(CxxGrammarImpl.postfixExpression, CxxGrammarImpl.initDeclarator)) {
            if (!CxxAstNodeHelper.isFunctionCall(node)
                    && !CxxConstructorCalls.isConstructorCall(node)) {
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
     * The findings whose detection (a rule matched on a call) is not reported below the root of
     * another finding. A finding is kept when every finding reporting its detection is itself
     * reported by it, so that two findings never remove each other. A finding with the same
     * detection as a kept one, reached through another call (e.g. a key passed to a setter of a
     * context created elsewhere), is the same finding and is not kept again. A call reported below
     * another finding by another rule is another detection, e.g. {@code EVP_SealInit} is both the
     * encryption with its cipher and the encryption of the session key with the key given to it.
     *
     * <p>A finding of a rule derived from another one (see {@link DerivedDetectionRules}) is also
     * reported by another finding when everything detected below it is detected below that finding:
     * the rule it is derived from detects no call of its own when it has no action, e.g. a setting
     * of a key generation context reported with the key.
     */
    @Nonnull
    private static <F extends Finding<?, AstNode, ?, ?>> List<F> withoutFindingsReportedByOthers(
            @Nonnull List<F> findings) {
        final List<Detection> roots = new ArrayList<>(findings.size());
        final List<Boolean> derived = new ArrayList<>(findings.size());
        final List<Set<Detection>> nestedDetections = new ArrayList<>(findings.size());
        final Map<Detection, List<Integer>> reportedBy = new HashMap<>();
        for (int i = 0; i < findings.size(); i++) {
            final DetectionStore<?, AstNode, ?, ?> store = findings.get(i).detectionStore();
            derived.add(
                    DerivedDetectionRules.origin(store.getDetectionRule())
                            != store.getDetectionRule());
            roots.add(
                    new Detection(
                            DerivedDetectionRules.origin(store.getDetectionRule()),
                            position(
                                    store.getDetectedExpression()
                                            .orElse(findings.get(i).getMarkerTree()))));
            final Set<Detection> nested = new HashSet<>();
            store.getChildren().forEach(child -> collectDetections(child, nested));
            nestedDetections.add(nested);
            for (Detection detection : nested) {
                reportedBy.computeIfAbsent(detection, d -> new ArrayList<>()).add(i);
            }
        }
        final List<F> kept = new ArrayList<>(findings.size());
        final Set<Detection> keptRoots = new HashSet<>();
        for (int i = 0; i < findings.size(); i++) {
            final int finding = i;
            final boolean reportedByAnother =
                    reportedBy.getOrDefault(roots.get(i), List.of()).stream()
                            .anyMatch(
                                    other ->
                                            other != finding
                                                    && !nestedDetections
                                                            .get(finding)
                                                            .contains(roots.get(other)));
            final boolean derivedAndReportedByAnother =
                    derived.get(i)
                            && !nestedDetections.get(i).isEmpty()
                            && IntStream.range(0, findings.size())
                                    .anyMatch(
                                            other ->
                                                    other != finding
                                                            && nestedDetections
                                                                    .get(other)
                                                                    .containsAll(
                                                                            nestedDetections.get(
                                                                                    finding)));
            if (!reportedByAnother && !derivedAndReportedByAnother && keptRoots.add(roots.get(i))) {
                kept.add(findings.get(i));
            }
        }
        return kept;
    }

    /**
     * The detections of a detection store and of the stores below it: the calls the rules matched,
     * and the values they found, which stand for a value found through a hook at the call of the
     * function it is passed to, e.g. {@code "SHA256"} in {@code sign("SHA256", key)} for the digest
     * of a signature made in {@code sign}, as no call of the store's rule is there.
     */
    private static void collectDetections(
            @Nonnull DetectionStore<?, AstNode, ?, ?> store, @Nonnull Set<Detection> detections) {
        final IDetectionRule<AstNode> rule = DerivedDetectionRules.origin(store.getDetectionRule());
        store.getDetectedExpressions()
                .forEach(expression -> detections.add(new Detection(rule, position(expression))));
        store.getDetectionValues()
                .forEach(
                        value ->
                                detections.add(new Detection(rule, position(value.getLocation()))));
        store.getChildren().forEach(child -> collectDetections(child, detections));
    }

    /**
     * A detection rule matched on the call at a position; the rule is compared by identity, a rule
     * derived from another one as the rule it is derived from (see {@link DerivedDetectionRules}).
     */
    private record Detection(@Nonnull IDetectionRule<?> rule, @Nonnull String position) {
        @Override
        public boolean equals(Object other) {
            return other instanceof Detection detection
                    && detection.rule == rule
                    && detection.position.equals(position);
        }

        @Override
        public int hashCode() {
            return 31 * System.identityHashCode(rule) + position.hashCode();
        }
    }

    /** Whether the translated nodes hold an asset (an algorithm, key, protocol or cipher suite). */
    private static boolean describesAnAsset(@Nonnull List<INode> nodes) {
        return nodes.stream()
                .anyMatch(
                        node ->
                                node instanceof IAsset
                                        || node instanceof IAssetCollection<?>
                                        || describesAnAsset(
                                                List.copyOf(node.getChildren().values())));
    }

    /** A node's position, by its first token: the matched calls may be detached copies. */
    @Nonnull
    private static String position(@Nonnull AstNode node) {
        return node.getToken().getLine() + ":" + node.getToken().getColumn();
    }

    /**
     * Called when a finding is detected by the engine. The finding is handled by {@link #onFinding}
     * once the file is traversed, see {@link #leaveFile}.
     *
     * @param finding A finding containing detection store information.
     */
    @Override
    public final void update(
            @Nonnull
                    Finding<
                                    SquidCheck<?>,
                                    AstNode,
                                    Symbol,
                                    SquidAstVisitorContext<? extends Grammar>>
                            finding) {
        fileFindings.add(finding);
    }

    /**
     * Handles a finding: adds its translation to the inventory and reports its issues.
     *
     * @param finding A finding containing detection store information.
     * @param nodes The translation of the finding.
     */
    protected void onFinding(
            @Nonnull
                    Finding<
                                    SquidCheck<?>,
                                    AstNode,
                                    Symbol,
                                    SquidAstVisitorContext<? extends Grammar>>
                            finding,
            @Nonnull List<INode> nodes) {
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
