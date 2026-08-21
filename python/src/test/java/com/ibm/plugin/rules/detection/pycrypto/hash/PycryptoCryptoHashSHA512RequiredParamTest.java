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
package com.ibm.plugin.rules.detection.pycrypto.hash;

import static com.ibm.engine.detection.MethodMatcher.ANY;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
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

/**
 * Verifies that a rule with a <em>required</em> named parameter does not fire when that parameter
 * is absent from the call site.
 *
 * <p>The rule used here mirrors {@code PycryptoCryptoHash.SHA512_NEW} except that {@code truncate}
 * is declared with {@code optional=false}. A call of {@code SHA512.new()} — which omits {@code
 * truncate} — must therefore produce no detection.
 */
class PycryptoCryptoHashSHA512RequiredParamTest extends TestBase {

    private static final String BASE_PATH = "src/test/files/rules/detection/pycrypto/hash/";

    /** Rule variant: truncate is required (optional=false). */
    private static final IDetectionRule<Tree> SHA512_NEW_TRUNCATE_REQUIRED =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Hash.SHA512")
                    .forMethods("new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA512"))
                    .withNamedMethodParameter("data", ANY, /* optional */ true)
                    .withNamedMethodParameter("truncate", "str", /* optional */ false)
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    public PycryptoCryptoHashSHA512RequiredParamTest() {
        super(List.of(SHA512_NEW_TRUNCATE_REQUIRED));
    }

    /**
     * SHA512.new() with a rule that declares {@code truncate} as required. The rule must NOT fire
     * because the required argument is absent.
     */
    @Test
    void testNegativeRequiredNamedParamAbsent() {
        PythonCheckVerifier.verifyNoIssue(
                BASE_PATH + "SHA512NewNegativeRequiredNamedParamAbsentTest.py", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull List<INode> nodes) {
        // This method must not be called: verifyNoIssue guarantees zero findings.
        throw new AssertionError(
                "No finding expected, but asserts() was called for finding #" + findingId);
    }
}
