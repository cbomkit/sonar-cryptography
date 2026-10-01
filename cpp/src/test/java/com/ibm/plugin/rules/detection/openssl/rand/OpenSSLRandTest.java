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
package com.ibm.plugin.rules.detection.openssl.rand;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.PRNGContext;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.PseudorandomNumberGenerator;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.plugin.CxxVerifier;
import com.ibm.plugin.TestBase;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

/**
 * Covers all 8 rule entries in {@link com.ibm.plugin.rules.detection.openssl.rand.OpenSSLRand}.
 *
 * <p><b>This test is the deep-assert reference for the C/C++ module.</b> Every other cpp detection
 * test class in this module references this Javadoc and follows the same pattern:
 *
 * <ol>
 *   <li>Verify detection-store structure: {@code getDetectionValues().hasSize(1)}, context class
 *       ({@link PRNGContext}, {@link com.ibm.engine.model.context.CipherContext}, {@link
 *       com.ibm.engine.model.context.MacContext} etc.), value type ({@link ValueAction} or
 *       library-specific {@code IAction}), and {@code asString()}.
 *   <li>Verify the translated {@link INode} tree returned by {@link
 *       com.ibm.plugin.translation.CxxTranslationProcess#initiate}: top-level node class (e.g.
 *       {@link AES}, {@link SHA2}), {@link INode#getKind()}, {@link INode#asString()}, and when the
 *       translator/enricher produces composite nodes, walk children with {@code
 *       node.getChildren().get(<ClassToken>.class)} (e.g. {@link com.ibm.mapper.model.Mode}, {@link
 *       com.ibm.mapper.model.KeyLength}, {@link com.ibm.mapper.model.BlockSize}, {@link
 *       com.ibm.mapper.model.Oid}, {@link com.ibm.mapper.model.MessageDigest}).
 * </ol>
 *
 * <p>Findings whose translator returns {@code Optional.empty()} (no model coverage yet) assert
 * {@code nodes.isEmpty()} — see e.g. {@code OpenSSLLegacyDigestTest} for the SHA1/SHA224/...
 * branches.
 */
class OpenSSLRandTest extends TestBase {

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/rand/OpenSSLRandTestFile.cc", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<
                                    SquidCheck<?>,
                                    AstNode,
                                    Symbol,
                                    SquidAstVisitorContext<? extends Grammar>>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        /* Detection Store — common to every finding */
        assertThat(detectionStore).isNotNull();
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(PRNGContext.class);
        IValue<AstNode> value = detectionStore.getDetectionValues().get(0);

        switch (findingId) {
            case 0, 1, 2, 3 -> {
                // RAND_bytes, RAND_priv_bytes, RAND_bytes_ex, RAND_priv_bytes_ex
                assertThat(value.asString()).isEqualTo("RAND");
                assertThat(nodes).hasSize(1);
                INode node = nodes.get(0);
                assertThat(node).isInstanceOf(Algorithm.class);
                assertThat(node.getKind()).isEqualTo(PseudorandomNumberGenerator.class);
                assertThat(node.asString()).isEqualTo("RAND");
            }
            case 4 -> {
                assertThat(value.asString()).isEqualTo("CTR-DRBG-AES128");
                assertDrbgAes(nodes, 128);
            }
            case 5 -> {
                assertThat(value.asString()).isEqualTo("CTR-DRBG-AES192");
                assertDrbgAes(nodes, 192);
            }
            case 6 -> {
                assertThat(value.asString()).isEqualTo("CTR-DRBG-AES256");
                assertDrbgAes(nodes, 256);
            }
            case 7 -> {
                assertThat(value.asString()).isEqualTo("HASH-DRBG-SHA1");
                assertDrbgSha(nodes);
            }
            case 8 -> {
                assertThat(value.asString()).isEqualTo("HASH-DRBG-SHA256");
                assertDrbgSha2(nodes, 256);
            }
            case 9 -> {
                assertThat(value.asString()).isEqualTo("HASH-DRBG-SHA384");
                assertDrbgSha2(nodes, 384);
            }
            case 10 -> {
                assertThat(value.asString()).isEqualTo("HASH-DRBG-SHA512");
                assertDrbgSha2(nodes, 512);
            }
            case 11 -> {
                assertThat(value.asString()).isEqualTo("HMAC-DRBG-SHA1");
                assertDrbgSha(nodes);
            }
            case 12 -> {
                assertThat(value.asString()).isEqualTo("HMAC-DRBG-SHA256");
                assertDrbgSha2(nodes, 256);
            }
            case 13 -> {
                assertThat(value.asString()).isEqualTo("HMAC-DRBG-SHA384");
                assertDrbgSha2(nodes, 384);
            }
            case 14 -> {
                assertThat(value.asString()).isEqualTo("HMAC-DRBG-SHA512");
                assertDrbgSha2(nodes, 512);
            }
            case 15 -> {
                assertThat(value.asString()).isEqualTo("SEED-SRC");
                assertThat(nodes).hasSize(1);
                INode node = nodes.get(0);
                assertThat(node).isInstanceOf(Algorithm.class);
                assertThat(node.getKind()).isEqualTo(PseudorandomNumberGenerator.class);
                assertThat(node.asString()).isEqualTo("SEED-SRC");
            }
            case 16 -> {
                assertThat(value.asString()).isEqualTo("JITTER");
                assertThat(nodes).hasSize(1);
                INode node = nodes.get(0);
                assertThat(node).isInstanceOf(Algorithm.class);
                assertThat(node.getKind()).isEqualTo(PseudorandomNumberGenerator.class);
                assertThat(node.asString()).isEqualTo("JITTER");
            }
            case 17 -> {
                assertThat(value.asString()).isEqualTo("TEST-RAND");
                assertThat(nodes).hasSize(1);
                INode node = nodes.get(0);
                assertThat(node).isInstanceOf(Algorithm.class);
                assertThat(node.getKind()).isEqualTo(PseudorandomNumberGenerator.class);
                assertThat(node.asString()).isEqualTo("TEST-RAND");
            }
            case 18 -> {
                // RAND_set_DRBG_type(NULL, "CTR-DRBG", NULL, NULL, NULL): drbg family name
                // resolved via CxxPRNGContextTranslator's bare-name case.
                assertThat(value.asString()).isEqualTo("CTR-DRBG");
                assertThat(nodes).hasSize(1);
                assertThat(nodes.get(0).asString()).isEqualTo("CTR-DRBG");
            }
            case 19 -> {
                // RAND_set_seed_source_type(NULL, "SEED-SRC", NULL): real captured value, same
                // vocabulary as the existing "SEED-SRC" case.
                assertThat(value.asString()).isEqualTo("SEED-SRC");
                assertThat(nodes).hasSize(1);
                assertThat(nodes.get(0).asString()).isEqualTo("SEED-SRC");
            }
            default -> throw new AssertionError("Unexpected findingId: " + findingId);
        }
    }

    private static void assertDrbgAes(List<INode> nodes, int keySize) {
        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node).isInstanceOf(AES.class);
        assertThat(node.getKind()).isEqualTo(PseudorandomNumberGenerator.class);
        assertThat(node.asString()).containsIgnoringCase("AES-" + keySize);
    }

    private static void assertDrbgSha(List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node).isInstanceOf(SHA.class);
        assertThat(node.getKind()).isEqualTo(PseudorandomNumberGenerator.class);
    }

    private static void assertDrbgSha2(List<INode> nodes, int digestSize) {
        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node).isInstanceOf(SHA2.class);
        assertThat(node.getKind()).isEqualTo(PseudorandomNumberGenerator.class);
        assertThat(node.asString()).contains(Integer.toString(digestSize));
    }
}
