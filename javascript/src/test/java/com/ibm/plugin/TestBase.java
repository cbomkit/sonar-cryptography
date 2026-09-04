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
import com.ibm.plugin.javascript.api.JavaScriptCheck;
import com.ibm.plugin.javascript.api.JavaScriptSymbol;
import com.ibm.plugin.javascript.api.Tree;
import com.ibm.plugin.javascript.language.JavaScriptScanContext;
import com.ibm.plugin.rules.JavaScriptInventoryRule;
import com.ibm.plugin.rules.detection.JavaScriptDetectionRules;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.junit.jupiter.api.BeforeEach;
import org.slf4j.event.Level;
import org.sonar.api.testfixtures.log.LogTesterJUnit5;

public abstract class TestBase extends JavaScriptInventoryRule {

    @Nonnull
    private final DetectionStoreLogger<
                    JavaScriptCheck, Tree, JavaScriptSymbol, JavaScriptScanContext>
            detectionStoreLogger = new DetectionStoreLogger<>();

    private int findingId = 0;
    private int updateCount = 0;

    public int getUpdateCount() {
        return updateCount;
    }

    public TestBase(@Nonnull List<IDetectionRule<Tree>> detectionRules) {
        super(detectionRules);
    }

    public TestBase() {
        super(JavaScriptDetectionRules.rules());
    }

    @BeforeEach
    public void resetState() {
        JavaScriptAggregator.reset();
    }

    @BeforeEach
    public void debug() {
        LogTesterJUnit5 logTesterJUnit5 = new LogTesterJUnit5();
        logTesterJUnit5.setLevel(Level.DEBUG);
    }

    @Override
    public void update(
            @Nonnull
                    Finding<JavaScriptCheck, Tree, JavaScriptSymbol, JavaScriptScanContext>
                            finding) {
        updateCount++;
        final DetectionStore<JavaScriptCheck, Tree, JavaScriptSymbol, JavaScriptScanContext>
                detectionStore = finding.detectionStore();
        detectionStoreLogger.print(detectionStore);

        List<INode> nodes = javascriptTranslationProcess.initiate(detectionStore);
        asserts(findingId, detectionStore, nodes);
        findingId++;
        if (!nodes.isEmpty()) {
            JavaScriptAggregator.addNodes(nodes);
        }
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
                    DetectionStore<JavaScriptCheck, Tree, JavaScriptSymbol, JavaScriptScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes);

    @Nullable public DetectionStore<JavaScriptCheck, Tree, JavaScriptSymbol, JavaScriptScanContext>
            getStoreOfValueType(
                    @Nonnull final Class<? extends IValue> valueType,
                    @Nonnull
                            List<
                                            DetectionStore<
                                                    JavaScriptCheck,
                                                    Tree,
                                                    JavaScriptSymbol,
                                                    JavaScriptScanContext>>
                                    detectionStores) {
        Optional<DetectionStore<JavaScriptCheck, Tree, JavaScriptSymbol, JavaScriptScanContext>>
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
}
