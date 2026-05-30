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
 * End-to-end location proof for issue #339 using the exact
 * pkg:maven/com.google.guava/guava@33.0.0-jre Hashing.java pattern.
 *
 * <p>The Guava pattern nests {@code new SecretKeySpec(...)} directly as an argument:
 *
 * <pre>
 *   return hmacMd5(new SecretKeySpec(checkNotNull(key), "HmacMD5"));
 * </pre>
 *
 * <p>The three-layer chain this test proves:
 *
 * <ol>
 *   <li><b>Source line</b>: the {@code new SecretKeySpec(...)} call in GuavaHashingTestFile.java
 *       (lines 65 / 89 / 113 / 137), mirroring Guava lines 306 / 330 / 354 / 378.
 *   <li><b>DetectionLocation.lineNumber()</b>: asserted via
 *       {@code ((IAsset) nodes.get(0)).getDetectionContext().lineNumber()}.
 *   <li><b>CBOM occurrence line</b>: {@code CBOMOutputFile.java:363} sets
 *       {@code occurrence.setLine(detectionLocation.lineNumber())} — the same value, verbatim.
 * </ol>
 *
 * <p>If all three columns match (source == DetectionLocation == CBOM), the fix is proven.
 */
// https://github.com/cbomkit/sonar-cryptography/issues/339
class GuavaHashingTest extends TestBase {

    /**
     * Verifies that the nested-SecretKeySpec pattern (Guava Hashing.java style) is detected at the
     * correct call-site lines, not at adjacent javadoc comments.
     *
     * <p>Evidence table (fixture line → Guava source line):
     *
     * <pre>
     * Fixture  Guava   Algorithm   DetectionLocation  CBOM occurrence
     * line 65  line 306  HmacMD5     65               65
     * line 89  line 330  HmacSHA1    89               89
     * line 113 line 354  HmacSHA256  113              113
     * line 137 line 378  HmacSHA512  137              137
     * </pre>
     */
    @Test
    void nestedSecretKeySpecIsDetectedAtCallSiteNotJavadoc() {
        CheckVerifier.newVerifier()
                .onFile("src/test/files/rules/issues/GuavaHashingTestFile.java")
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
                // hmacMd5(new SecretKeySpec(key, "HmacMD5")) — fixture line 65, Guava line 306
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(SecretKeyContext.class);
                assertThat(detectionStore.getDetectionValues()).hasSize(1);
                IValue<Tree> value = detectionStore.getDetectionValues().get(0);
                assertThat(value).isInstanceOf(Algorithm.class);
                assertThat(value.asString()).isEqualTo("HmacMD5");
                // Layer 2 → 3: DetectionLocation.lineNumber() == CBOM occurrence.line (same value)
                assertThat(nodes).isNotEmpty();
                assertThat(nodes.get(0)).isInstanceOf(IAsset.class);
                assertThat(((IAsset) nodes.get(0)).getDetectionContext().lineNumber())
                        .as("fixture line 65 == Guava line 306 (HmacMD5 SecretKeySpec)")
                        .isEqualTo(65);
            }
            case 1 -> {
                // hmacSha1(new SecretKeySpec(key, "HmacSHA1")) — fixture line 89, Guava line 330
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(SecretKeyContext.class);
                assertThat(detectionStore.getDetectionValues()).hasSize(1);
                IValue<Tree> value = detectionStore.getDetectionValues().get(0);
                assertThat(value).isInstanceOf(Algorithm.class);
                assertThat(value.asString()).isEqualTo("HmacSHA1");
                assertThat(nodes).isNotEmpty();
                assertThat(nodes.get(0)).isInstanceOf(IAsset.class);
                assertThat(((IAsset) nodes.get(0)).getDetectionContext().lineNumber())
                        .as("fixture line 89 == Guava line 330 (HmacSHA1 SecretKeySpec)")
                        .isEqualTo(89);
            }
            case 2 -> {
                // hmacSha256(new SecretKeySpec(key, "HmacSHA256")) — fixture line 113, Guava line 354
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(SecretKeyContext.class);
                assertThat(detectionStore.getDetectionValues()).hasSize(1);
                IValue<Tree> value = detectionStore.getDetectionValues().get(0);
                assertThat(value).isInstanceOf(Algorithm.class);
                assertThat(value.asString()).isEqualTo("HmacSHA256");
                assertThat(nodes).isNotEmpty();
                assertThat(nodes.get(0)).isInstanceOf(IAsset.class);
                assertThat(((IAsset) nodes.get(0)).getDetectionContext().lineNumber())
                        .as("fixture line 113 == Guava line 354 (HmacSHA256 SecretKeySpec)")
                        .isEqualTo(113);
            }
            case 3 -> {
                // hmacSha512(new SecretKeySpec(key, "HmacSHA512")) — fixture line 137, Guava line 378
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(SecretKeyContext.class);
                assertThat(detectionStore.getDetectionValues()).hasSize(1);
                IValue<Tree> value = detectionStore.getDetectionValues().get(0);
                assertThat(value).isInstanceOf(Algorithm.class);
                assertThat(value.asString()).isEqualTo("HmacSHA512");
                assertThat(nodes).isNotEmpty();
                assertThat(nodes.get(0)).isInstanceOf(IAsset.class);
                assertThat(((IAsset) nodes.get(0)).getDetectionContext().lineNumber())
                        .as("fixture line 137 == Guava line 378 (HmacSHA512 SecretKeySpec)")
                        .isEqualTo(137);
            }
            default -> fail("Unexpected findingId: " + findingId);
        }
    }
}
