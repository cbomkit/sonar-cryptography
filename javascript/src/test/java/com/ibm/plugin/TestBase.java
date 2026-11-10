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
package com.ibm.plugin;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.detection.Finding;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.RuleSets;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.javascript.language.JavaScriptCheck;
import com.ibm.plugin.javascript.language.JavaScriptScanContext;
import com.ibm.plugin.javascript.language.JavaScriptSymbol;
import com.ibm.plugin.javascript.tree.JavaScriptTree;
import com.ibm.plugin.rules.JavaScriptInventoryRule;
import com.ibm.plugin.rules.detection.JavaScriptDetectionRules;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.BeforeEach;

/**
 * Base class for detection rule tests: runs the pipeline and hands each finding to {@link
 * #asserts}.
 */
public abstract class TestBase extends JavaScriptInventoryRule {

    private int findingId = 0;

    public TestBase(@Nonnull List<IDetectionRule<JavaScriptTree>> detectionRules) {
        super(detectionRules);
    }

    public TestBase() {
        super(RuleSets.rulesOf(JavaScriptDetectionRules.class));
    }

    @BeforeEach
    public void resetState() {
        JavaScriptAggregator.reset();
        findingId = 0;
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
        final DetectionStore<
                        JavaScriptCheck, JavaScriptTree, JavaScriptSymbol, JavaScriptScanContext>
                detectionStore = finding.detectionStore();
        final List<INode> nodes = javascriptTranslationProcess.initiate(detectionStore);
        asserts(findingId, detectionStore, nodes);
        findingId++;
    }

    /** Number of findings observed so far in the current test. */
    protected int findingCount() {
        return findingId;
    }

    public abstract void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<
                                    JavaScriptCheck,
                                    JavaScriptTree,
                                    JavaScriptSymbol,
                                    JavaScriptScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes);
}
