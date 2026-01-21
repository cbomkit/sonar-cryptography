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
import com.ibm.engine.language.go.GoScanContext;
import com.ibm.engine.model.IValue;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.utils.DetectionStoreLogger;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.rules.GoInventoryRule;
import com.ibm.plugin.rules.detection.GoDetectionRules;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.junit.Before;
import org.slf4j.event.Level;
import org.sonar.api.testfixtures.log.LogTesterJUnit5;
import org.sonar.go.symbols.Symbol;
import org.sonar.plugins.go.api.Tree;
import org.sonar.plugins.go.api.checks.GoCheck;

public abstract class TestBase extends GoInventoryRule {

    @Nonnull
    private final DetectionStoreLogger<GoCheck, Tree, Symbol, GoScanContext> detectionStoreLogger =
            new DetectionStoreLogger<>();

    private int findingId = 0;

    public TestBase(@Nonnull List<IDetectionRule<Tree>> detectionRules) {
        super(detectionRules);
    }

    public TestBase() {
        super(GoDetectionRules.rules());
    }

    @Before
    public void debug() {
        LogTesterJUnit5 logTesterJUnit5 = new LogTesterJUnit5();
        logTesterJUnit5.setLevel(Level.DEBUG);
    }

    @Override
    public void update(@Nonnull Finding<GoCheck, Tree, Symbol, GoScanContext> finding) {
        final DetectionStore<GoCheck, Tree, Symbol, GoScanContext> detectionStore =
                finding.detectionStore();
        detectionStoreLogger.print(detectionStore);

        List<INode> nodes = goTranslationProcess.initiate(detectionStore);
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
            @Nonnull DetectionStore<GoCheck, Tree, Symbol, GoScanContext> detectionStore,
            @Nonnull List<INode> nodes);

    @Nullable public DetectionStore<GoCheck, Tree, Symbol, GoScanContext> getStoreOfValueType(
            @Nonnull final Class<? extends IValue> valueType,
            @Nonnull List<DetectionStore<GoCheck, Tree, Symbol, GoScanContext>> detectionStores) {
        Optional<DetectionStore<GoCheck, Tree, Symbol, GoScanContext>> relevantStore =
                detectionStores.stream()
                        .filter(
                                store ->
                                        store.getDetectionValues().stream()
                                                .anyMatch(
                                                        value ->
                                                                value.getClass().equals(valueType)))
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

    @Nullable public List<DetectionStore<GoCheck, Tree, Symbol, GoScanContext>> getStoresOfValueType(
            @Nonnull final Class<? extends IValue> valueType,
            @Nonnull List<DetectionStore<GoCheck, Tree, Symbol, GoScanContext>> detectionStores) {
        return detectionStores.stream()
                .filter(
                        store ->
                                store.getDetectionValues().stream()
                                        .anyMatch(value -> value.getClass().equals(valueType)))
                .toList();
    }
}
