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
package com.ibm.plugin;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.detection.Finding;
import com.ibm.engine.model.IValue;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.utils.DetectionStoreLogger;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.rules.CxxInventoryRule;
import com.ibm.plugin.rules.detection.CxxDetectionRules;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.junit.jupiter.api.BeforeEach;
import org.slf4j.event.Level;
import org.sonar.api.testfixtures.log.LogTesterJUnit5;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

public abstract class TestBase extends CxxInventoryRule {

    @Nonnull
    private final DetectionStoreLogger<
                    SquidCheck<?>, AstNode, Symbol, SquidAstVisitorContext<? extends Grammar>>
            detectionStoreLogger = new DetectionStoreLogger<>();

    private int findingId = 0;

    public TestBase(@Nonnull List<IDetectionRule<AstNode>> detectionRules) {
        super(detectionRules);
    }

    public TestBase() {
        super(CxxDetectionRules.rules());
    }

    @BeforeEach
    public void resetState() {
        CxxAggregator.reset();
    }

    @BeforeEach
    public void debug() {
        LogTesterJUnit5 logTesterJUnit5 = new LogTesterJUnit5();
        logTesterJUnit5.setLevel(Level.DEBUG);
    }

    @Override
    public void update(
            @Nonnull
                    Finding<
                                    SquidCheck<?>,
                                    AstNode,
                                    Symbol,
                                    SquidAstVisitorContext<? extends Grammar>>
                            finding) {
        final DetectionStore<
                        SquidCheck<?>, AstNode, Symbol, SquidAstVisitorContext<? extends Grammar>>
                detectionStore = finding.detectionStore();
        detectionStoreLogger.print(detectionStore);

        final List<INode> nodes = cxxTranslationProcess.initiate(detectionStore);
        asserts(findingId, detectionStore, nodes);
        findingId++;
        // report
        this.report(finding.getMarkerTree(), nodes)
                .forEach(
                        issue ->
                                finding.detectionStore()
                                        .getScanContext()
                                        .reportIssue(this, issue.tree(), issue.message()));
    }

    public abstract void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<
                                    SquidCheck<?>,
                                    AstNode,
                                    Symbol,
                                    SquidAstVisitorContext<? extends Grammar>>
                            detectionStore,
            @Nonnull List<INode> nodes);

    @Nullable public DetectionStore<SquidCheck<?>, AstNode, Symbol, SquidAstVisitorContext<? extends Grammar>>
            getStoreWithValue(
                    @Nonnull
                            List<
                                            DetectionStore<
                                                    SquidCheck<?>,
                                                    AstNode,
                                                    Symbol,
                                                    SquidAstVisitorContext<? extends Grammar>>>
                                    detectionStores) {
        return detectionStores.stream()
                .filter(store -> !store.getDetectionValues().isEmpty())
                .findFirst()
                .orElse(null);
    }

    @Nullable public DetectionStore<SquidCheck<?>, AstNode, Symbol, SquidAstVisitorContext<? extends Grammar>>
            getStoreOfValueType(
                    @Nonnull final Class<? extends IValue> valueType,
                    @Nonnull
                            List<
                                            DetectionStore<
                                                    SquidCheck<?>,
                                                    AstNode,
                                                    Symbol,
                                                    SquidAstVisitorContext<? extends Grammar>>>
                                    detectionStores) {
        Optional<
                        DetectionStore<
                                SquidCheck<?>,
                                AstNode,
                                Symbol,
                                SquidAstVisitorContext<? extends Grammar>>>
                relevantStore =
                        detectionStores.stream()
                                .filter(
                                        store ->
                                                store.getDetectionValues().stream()
                                                        .anyMatch(
                                                                value ->
                                                                        value.getClass()
                                                                                .equals(valueType)))
                                .findFirst();
        return relevantStore.orElseGet(
                () ->
                        detectionStores.stream()
                                .map(
                                        store ->
                                                Optional.ofNullable(
                                                        getStoreOfValueType(
                                                                valueType, store.getChildren())))
                                .filter(Optional::isPresent)
                                .map(Optional::get)
                                .findFirst()
                                .orElse(null));
    }

    @Nullable public List<
                    DetectionStore<
                            SquidCheck<?>,
                            AstNode,
                            Symbol,
                            SquidAstVisitorContext<? extends Grammar>>>
            getStoresOfValueType(
                    @Nonnull final Class<? extends IValue> valueType,
                    @Nonnull
                            List<
                                            DetectionStore<
                                                    SquidCheck<?>,
                                                    AstNode,
                                                    Symbol,
                                                    SquidAstVisitorContext<? extends Grammar>>>
                                    detectionStores) {
        List<
                        DetectionStore<
                                SquidCheck<?>,
                                AstNode,
                                Symbol,
                                SquidAstVisitorContext<? extends Grammar>>>
                relevantStores =
                        detectionStores.stream()
                                .filter(
                                        store ->
                                                store.getDetectionValues().stream()
                                                        .anyMatch(
                                                                value ->
                                                                        value.getClass()
                                                                                .equals(valueType)))
                                .toList();
        List<
                        DetectionStore<
                                SquidCheck<?>,
                                AstNode,
                                Symbol,
                                SquidAstVisitorContext<? extends Grammar>>>
                children =
                        detectionStores.stream()
                                .map(store -> getStoresOfValueType(valueType, store.getChildren()))
                                .filter(Objects::nonNull)
                                .flatMap(List::stream)
                                .toList();
        List<
                        DetectionStore<
                                SquidCheck<?>,
                                AstNode,
                                Symbol,
                                SquidAstVisitorContext<? extends Grammar>>>
                res = new ArrayList<>(relevantStores);
        res.addAll(children);
        return res;
    }
}
