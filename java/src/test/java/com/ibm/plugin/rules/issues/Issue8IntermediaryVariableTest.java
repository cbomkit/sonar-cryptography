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
package com.ibm.plugin.rules.issues;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class Issue8IntermediaryVariableTest extends TestBase {

    static IDetectionContext detectionContext =
            new IDetectionContext() {
                @Nonnull
                @Override
                public Class<? extends IDetectionContext> type() {
                    return IDetectionContext.class;
                }
            };

    public static List<IDetectionRule<Tree>> seatRules =
            List.of(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes(
                                    "com.ibm.example.Issue8IntermediaryVariableTestFile$LeatherSeats")
                            .forConstructor()
                            .shouldBeDetectedAs(new ValueActionFactory<>("LeatherSeats"))
                            .withoutParameters()
                            .buildForContext(detectionContext)
                            .inBundle(() -> "testBundle")
                            .withoutDependingDetectionRules());

    public Issue8IntermediaryVariableTest() {
        super(
                List.of(
                        new DetectionRuleBuilder<Tree>()
                                .createDetectionRule()
                                .forObjectTypes(
                                        "com.ibm.example.Issue8IntermediaryVariableTestFile$Car")
                                .forConstructor()
                                .shouldBeDetectedAs(new ValueActionFactory<>("Car"))
                                .withMethodParameter(
                                        "com.ibm.example.Issue8IntermediaryVariableTestFile$SeatInterface")
                                .addDependingDetectionRules(seatRules)
                                .buildForContext(detectionContext)
                                .inBundle(() -> "testBundle")
                                .withoutDependingDetectionRules()));
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(ValueAction.class);
        assertThat(value0.asString()).isEqualTo("Car");

        List<DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext>> stores =
                getStoresOfValueType(ValueAction.class, detectionStore.getChildren());

        assertThat(stores).hasSize(1);

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1 = stores.get(0);
        assertThat(store_1.getDetectionValues()).hasSize(1);
        IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
        assertThat(value0_1).isInstanceOf(ValueAction.class);
        assertThat(value0_1.asString()).isEqualTo("LeatherSeats");
    }

    @Override
    public void update(
            @Nonnull
                    com.ibm.engine.detection.Finding<
                                    JavaCheck, Tree, Symbol, JavaFileScannerContext>
                            finding) {
        super.update(finding);
        finding.detectionStore()
                .getDetectionValues()
                .forEach(
                        iValue -> {
                            this.reportIssue(iValue.getLocation(), iValue.asString());
                        });
    }

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile("src/test/files/rules/issues/Issue8IntermediaryVariableTestFile.java")
                .withChecks(this)
                .verifyIssues();
    }
}
