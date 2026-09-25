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

import static com.ibm.engine.detection.MethodMatcher.ANY;
import static org.assertj.core.api.Assertions.fail;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.Tree;
import org.sonar.python.checks.utils.PythonCheckVerifier;

class NamedParameterWildcardTest extends TestBase {

    NamedParameterWildcardTest() {
        super(
                List.of(
                        new DetectionRuleBuilder<Tree>()
                                .createDetectionRule()
                                .forObjectTypes("test.module.Foo")
                                .forMethods("f")
                                .shouldBeDetectedAs(new ValueActionFactory<>("f"))
                                .withMethodParameter(ANY)
                                .withNamedMethodParameter("b", "int")
                                .buildForContext(new DigestContext())
                                .inBundle(() -> "Test")
                                .withoutDependingDetectionRules()));
    }

    @Test
    void keywordForNamedParameterCannotFillPositionalSlot() {
        PythonCheckVerifier.verifyNoIssue(
                "src/test/files/rules/detection/named_parameters/FNegativePositionalSlotClaimedTest.py",
                this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull List<INode> nodes) {
        fail("A missing positional argument must not produce a finding");
    }
}
