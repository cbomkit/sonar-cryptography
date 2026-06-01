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
package com.ibm.plugin.rules.issues;

import static com.ibm.plugin.rules.detection.TypeShortcuts.STRING_TYPE;
import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.detection.Finding;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.engine.utils.DetectionStoreLogger;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.TestBase;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class DuplicateDependingRules2Test extends TestBase {

    static DetectionContext detectionContext =
            new DetectionContext(Map.of()) {
                @Nonnull
                @Override
                public Class<? extends DetectionContext> type() {
                    return DetectionContext.class;
                }
            };

    public DuplicateDependingRules2Test() {
        super(
                List.of(
                        new DetectionRuleBuilder<Tree>()
                                .createDetectionRule()
                                .forObjectTypes(
                                        "com.ibm.example.DuplicateDependingRules2TestFile$ExampleObject")
                                .forConstructor()
                                .shouldBeDetectedAs(new ValueActionFactory<>("ExampleObject"))
                                .withMethodParameter(STRING_TYPE)
                                .shouldBeDetectedAs(new AlgorithmFactory<>())
                                .asChildOfParameterWithId(-1)
                                .buildForContext(detectionContext)
                                .inBundle(() -> "testBundle")
                                .withDependingDetectionRules(
                                        List.of(
                                                new DetectionRuleBuilder<Tree>()
                                                        .createDetectionRule()
                                                        .forObjectTypes(
                                                                "com.ibm.example.DuplicateDependingRules2TestFile$ExampleObject")
                                                        .forMethods("init")
                                                        .withMethodParameter(STRING_TYPE)
                                                        .shouldBeDetectedAs(
                                                                new AlgorithmFactory<>())
                                                        .buildForContext(detectionContext)
                                                        .inBundle(() -> "testBundle")
                                                        .withoutDependingDetectionRules()))));
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        /*
         * Detection Store
         */

        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(ValueAction.class);
        assertThat(value0.asString()).isEqualTo("ExampleObject");

        List<DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext>> stores =
                getStoresOfValueType(Algorithm.class, detectionStore.getChildren());
        assertThat(stores).hasSize(2);

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1 = stores.get(0);
        assertThat(store_1.getDetectionValues()).hasSize(1);
        IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
        assertThat(value0_1).isInstanceOf(Algorithm.class);
        assertThat(value0_1.asString()).isEqualTo("InitParamValue");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_2 = stores.get(1);
        assertThat(store_2.getDetectionValues()).hasSize(1);
        IValue<Tree> value0_2 = store_2.getDetectionValues().get(0);
        assertThat(value0_2).isInstanceOf(Algorithm.class);
        assertThat(value0_2.asString()).isEqualTo("ExampleParamValue");
    }

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile("src/test/files/rules/issues/DuplicateDependingRules2TestFile.java")
                .withChecks(this)
                .verifyIssues();
    }

    @Override
    public void update(@Nonnull Finding<JavaCheck, Tree, Symbol, JavaFileScannerContext> finding) {
        final DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore =
                finding.detectionStore();
        (new DetectionStoreLogger<JavaCheck, Tree, Symbol, JavaFileScannerContext>())
                .print(detectionStore);
        detectionStore
                .getDetectionValues()
                .forEach(
                        iValue -> {
                            this.reportIssue(iValue.getLocation(), iValue.asString());
                        });
    }
}
