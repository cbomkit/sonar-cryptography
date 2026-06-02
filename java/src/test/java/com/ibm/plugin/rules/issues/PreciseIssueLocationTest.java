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

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.fail;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.MacContext;
import com.ibm.engine.model.context.SecretKeyContext;
import com.ibm.mapper.model.IAsset;
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

/**
 * Regression test for issue #339: Detection location off - Findings reported below the actual
 * place.
 *
 * <p>When scanning code that has methods separated by multi-line javadoc comments (like Guava's
 * Hashing.java), all findings were reported at the closing {@code * /} of the <em>next</em>
 * method's javadoc comment instead of at the actual detection site.
 *
 * <p>This test verifies that:
 *
 * <ol>
 *   <li>Findings for {@code new SecretKeySpec(...)} are reported on the line of the constructor
 *       call, not on the javadoc comment of the following method.
 *   <li>Findings for {@code Mac.getInstance(...)} are reported on the line of the method
 *       invocation, not on the javadoc comment of the following method.
 * </ol>
 *
 * <p>The test fixture {@code PreciseIssueLocationTestFile.java} reproduces the Guava Hashing.java
 * pattern exactly: each method is separated from the next by a multi-line {@code /** ... * /}
 * javadoc block.
 */
// https://github.com/cbomkit/sonar-cryptography/issues/339
class PreciseIssueLocationTest extends TestBase {

    /**
     * Verifies that issues are reported at the correct lines (i.e., at the {@code //Noncompliant}
     * markers in the test fixture, which are placed on the actual call-site lines, NOT on the
     * closing {@code * /} of adjacent javadoc comments).
     */
    @Test
    void reportsIssuesOnCallSiteNotJavadoc() {
        CheckVerifier.newVerifier()
                .onFile("src/test/files/rules/issues/PreciseIssueLocationTestFile.java")
                .withChecks(this)
                .verifyIssues();
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        switch (findingId) {
            case 0 -> {
                // new SecretKeySpec(key, "HmacMD5") in hmacMd5(byte[] key)
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(SecretKeyContext.class);
                assertThat(detectionStore.getDetectionValues()).hasSize(1);
                IValue<Tree> value = detectionStore.getDetectionValues().get(0);
                assertThat(value).isInstanceOf(Algorithm.class);
                assertThat(value.asString()).isEqualTo("HmacMD5");
                // Regression for #339: occurrence must point to the call site (line 23), not
                // javadoc
                assertThat(nodes).isNotEmpty();
                assertThat(nodes.get(0)).isInstanceOf(IAsset.class);
                assertThat(((IAsset) nodes.get(0)).getDetectionContext().lineNumber())
                        .isEqualTo(23);
            }
            case 1 -> {
                // Mac.getInstance("HmacMD5") in hmacMd5(Key key)
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(MacContext.class);
                assertThat(detectionStore.getDetectionValues()).hasSize(1);
                IValue<Tree> value = detectionStore.getDetectionValues().get(0);
                assertThat(value).isInstanceOf(Algorithm.class);
                assertThat(value.asString()).isEqualTo("HmacMD5");
                // Regression for #339: occurrence must point to the call site (line 35), not
                // javadoc
                assertThat(nodes).isNotEmpty();
                assertThat(nodes.get(0)).isInstanceOf(IAsset.class);
                assertThat(((IAsset) nodes.get(0)).getDetectionContext().lineNumber())
                        .isEqualTo(35);
            }
            case 2 -> {
                // new SecretKeySpec(key, "HmacSHA256") in hmacSha256(byte[] key)
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(SecretKeyContext.class);
                assertThat(detectionStore.getDetectionValues()).hasSize(1);
                IValue<Tree> value = detectionStore.getDetectionValues().get(0);
                assertThat(value).isInstanceOf(Algorithm.class);
                assertThat(value.asString()).isEqualTo("HmacSHA256");
                // Regression for #339: occurrence must point to the call site (line 53), not
                // javadoc
                assertThat(nodes).isNotEmpty();
                assertThat(nodes.get(0)).isInstanceOf(IAsset.class);
                assertThat(((IAsset) nodes.get(0)).getDetectionContext().lineNumber())
                        .isEqualTo(53);
            }
            case 3 -> {
                // Mac.getInstance("HmacSHA256") in hmacSha256(Key key)
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(MacContext.class);
                assertThat(detectionStore.getDetectionValues()).hasSize(1);
                IValue<Tree> value = detectionStore.getDetectionValues().get(0);
                assertThat(value).isInstanceOf(Algorithm.class);
                assertThat(value.asString()).isEqualTo("HmacSHA256");
                // Regression for #339: occurrence must point to the call site (line 67), not
                // javadoc
                assertThat(nodes).isNotEmpty();
                assertThat(nodes.get(0)).isInstanceOf(IAsset.class);
                assertThat(((IAsset) nodes.get(0)).getDetectionContext().lineNumber())
                        .isEqualTo(67);
            }
            default -> fail("Unexpected findingId: " + findingId);
        }
    }
}
