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
package com.ibm.plugin.rules.detection.openssl.digest;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.ExtendableOutputFunction;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.ParameterSetIdentifier;
import com.ibm.mapper.model.algorithms.MD2;
import com.ibm.mapper.model.algorithms.MD4;
import com.ibm.mapper.model.algorithms.MD5;
import com.ibm.mapper.model.algorithms.RIPEMD;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.SHA3;
import com.ibm.mapper.model.algorithms.SM3;
import com.ibm.mapper.model.algorithms.Whirlpool;
import com.ibm.mapper.model.algorithms.blake.BLAKE2b;
import com.ibm.mapper.model.algorithms.blake.BLAKE2s;
import com.ibm.mapper.model.algorithms.shake.SHAKE;
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
 * Covers all rule entries in {@link OpenSSLEvpMessageDigest}.
 *
 * <p>Follows the deep-assert pattern documented in {@link
 * com.ibm.plugin.rules.detection.openssl.rand.OpenSSLRandTest}.
 */
class OpenSSLEvpMessageDigestTest extends TestBase {

    private int findingCount = 0;

    @Test
    void test() {
        CxxVerifier.verify(
                "rules/detection/openssl/digest/OpenSSLEvpMessageDigestTestFile.cc", this);
        assertThat(findingCount).isEqualTo(31);
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
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(DigestContext.class);
        IValue<AstNode> value = detectionStore.getDetectionValues().get(0);
        findingCount++;

        switch (findingId) {
            case 0 -> {
                assertThat(value.asString()).isEqualTo("MD2");
                assertDigest(nodes, MD2.class, "MD2", 128, 128);
            }
            case 1 -> {
                assertThat(value.asString()).isEqualTo("MD4");
                assertDigest(nodes, MD4.class, "MD4", 128, 512);
            }
            case 2 -> {
                assertThat(value.asString()).isEqualTo("MD5");
                assertDigest(nodes, MD5.class, "MD5", 128, 512);
            }
            case 3 -> {
                assertThat(value.asString()).isEqualTo("MDC2");
                INode n = head(nodes);
                assertThat(n).isInstanceOf(Algorithm.class);
                assertThat(n.getKind()).isEqualTo(MessageDigest.class);
                assertThat(n.asString()).isEqualTo("MDC2");
            }
            case 4 -> {
                assertThat(value.asString()).isEqualTo("SHA-1");
                assertDigest(nodes, SHA.class, "SHA-1", 160, 512);
            }
            case 5 -> {
                assertThat(value.asString()).isEqualTo("SHA-224");
                assertDigest(nodes, SHA2.class, "SHA-224", 224, 512);
            }
            case 6 -> {
                assertThat(value.asString()).isEqualTo("SHA-256");
                assertDigest(nodes, SHA2.class, "SHA-256", 256, 512);
            }
            case 7 -> {
                assertThat(value.asString()).isEqualTo("SHA-384");
                assertDigest(nodes, SHA2.class, "SHA-384", 384, 1024);
            }
            case 8 -> {
                assertThat(value.asString()).isEqualTo("SHA-512");
                assertDigest(nodes, SHA2.class, "SHA-512", 512, 1024);
            }
            case 9 -> {
                assertThat(value.asString()).isEqualTo("SHA-512/224");
                assertSha512t(nodes, 224);
            }
            case 10 -> {
                assertThat(value.asString()).isEqualTo("SHA-512/256");
                assertSha512t(nodes, 256);
            }
            case 11 -> {
                assertThat(value.asString()).isEqualTo("SHA3-224");
                assertDigest(nodes, SHA3.class, "SHA3-224", 224, 1152);
            }
            case 12 -> {
                assertThat(value.asString()).isEqualTo("SHA3-256");
                assertDigest(nodes, SHA3.class, "SHA3-256", 256, 1088);
            }
            case 13 -> {
                assertThat(value.asString()).isEqualTo("SHA3-384");
                assertDigest(nodes, SHA3.class, "SHA3-384", 384, 832);
            }
            case 14 -> {
                assertThat(value.asString()).isEqualTo("SHA3-512");
                assertDigest(nodes, SHA3.class, "SHA3-512", 512, 576);
            }
            case 15 -> {
                assertThat(value.asString()).isEqualTo("SHAKE128");
                assertShake(nodes, "SHAKE128", 128);
            }
            case 16 -> {
                assertThat(value.asString()).isEqualTo("SHAKE256");
                assertShake(nodes, "SHAKE256", 256);
            }
            case 17 -> {
                assertThat(value.asString()).isEqualTo("RIPEMD160");
                INode n = head(nodes);
                assertThat(n).isInstanceOf(RIPEMD.class);
                assertThat(n.getKind()).isEqualTo(MessageDigest.class);
                assertThat(n.asString()).isEqualTo("RIPEMD-160");
                INode size = n.getChildren().get(DigestSize.class);
                assertThat(size).isNotNull();
                assertThat(size.asString()).isEqualTo("160");
            }
            case 18 -> {
                assertThat(value.asString()).isEqualTo("WHIRLPOOL");
                INode n = head(nodes);
                assertThat(n).isInstanceOf(Whirlpool.class);
                assertThat(n.getKind()).isEqualTo(MessageDigest.class);
                assertThat(n.asString()).isEqualTo("Whirlpool");
                assertThat(n.getChildren().get(DigestSize.class).asString()).isEqualTo("512");
                assertThat(n.getChildren().get(BlockSize.class).asString()).isEqualTo("512");
            }
            case 19 -> {
                assertThat(value.asString()).isEqualTo("BLAKE2B-512");
                INode n = head(nodes);
                assertThat(n).isInstanceOf(BLAKE2b.class);
                assertThat(n.getKind()).isEqualTo(MessageDigest.class);
                assertThat(n.asString()).isEqualTo("BLAKE2b-512");
                assertThat(n.getChildren().get(DigestSize.class).asString()).isEqualTo("512");
            }
            case 20 -> {
                assertThat(value.asString()).isEqualTo("BLAKE2S-256");
                INode n = head(nodes);
                assertThat(n).isInstanceOf(BLAKE2s.class);
                assertThat(n.getKind()).isEqualTo(MessageDigest.class);
                assertThat(n.asString()).isEqualTo("BLAKE2s-256");
                assertThat(n.getChildren().get(DigestSize.class).asString()).isEqualTo("256");
            }
            case 21 -> {
                assertThat(value.asString()).isEqualTo("SM3");
                INode n = head(nodes);
                assertThat(n).isInstanceOf(SM3.class);
                assertThat(n.getKind()).isEqualTo(MessageDigest.class);
                assertThat(n.asString()).isEqualTo("SM3");
                assertThat(n.getChildren().get(DigestSize.class).asString()).isEqualTo("256");
            }
            case 22 -> {
                // EVP_md5_sha1 → translator yields MD5 node
                assertThat(value.asString()).isEqualTo("MD5-SHA1");
                assertDigest(nodes, MD5.class, "MD5", 128, 512);
            }
            case 23 -> {
                assertThat(value.asString()).isEqualTo("NULL");
                assertThat(nodes).isEmpty();
            }
            case 24, 25 -> {
                // EVP_MD_fetch(NULL, "SHA256", NULL) / EVP_get_digestbyname("SHA256"): real
                // algorithm name resolved via OpenSSLNameCanonicalizerFactory.
                assertThat(value.asString()).isEqualTo("SHA-256");
                assertDigest(nodes, SHA2.class, "SHA-256", 256, 512);
            }
            case 26, 27, 28 -> {
                // EVP_DigestInit(_ex/_ex2)(ctx, NULL, ...): digest argument is a literal NULL,
                // so there is no constructing call to trace back to and the marker resolves to
                // no node.
                assertThat(value.asString()).isEqualTo("DIGEST");
                assertThat(nodes).isEmpty();
            }
            case 29 -> {
                // EVP_MD_fetch(NULL, digest_name, NULL): digest_name is a local variable,
                // resolved via CxxSymbolResolverVisitor from its initializer.
                assertThat(value.asString()).isEqualTo("SHA-256");
                assertDigest(nodes, SHA2.class, "SHA-256", 256, 512);
            }
            case 30 -> {
                // EVP_MD_fetch(NULL, "SHA2-256", NULL): OpenSSL 3.x provider fetch name
                // resolved via OpenSSLNameCanonicalizerFactory.
                assertThat(value.asString()).isEqualTo("SHA-256");
                assertDigest(nodes, SHA2.class, "SHA-256", 256, 512);
            }
            default -> throw new AssertionError("Unexpected findingId: " + findingId);
        }
    }

    /* helpers */

    private static INode head(List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        return nodes.get(0);
    }

    private static void assertDigest(
            List<INode> nodes,
            Class<? extends INode> klass,
            String asString,
            int digestSize,
            int blockSize) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(klass);
        assertThat(n.getKind()).isEqualTo(MessageDigest.class);
        assertThat(n.asString()).isEqualTo(asString);
        INode ds = n.getChildren().get(DigestSize.class);
        assertThat(ds).isNotNull();
        assertThat(ds.asString()).isEqualTo(Integer.toString(digestSize));
        INode bs = n.getChildren().get(BlockSize.class);
        assertThat(bs).isNotNull();
        assertThat(bs.asString()).isEqualTo(Integer.toString(blockSize));
    }

    private static void assertSha512t(List<INode> nodes, int truncLen) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(SHA2.class);
        assertThat(n.getKind()).isEqualTo(MessageDigest.class);
        assertThat(n.asString()).isEqualTo("SHA-512/" + truncLen);
        INode ds = n.getChildren().get(DigestSize.class);
        assertThat(ds).isNotNull();
        assertThat(ds.asString()).isEqualTo(Integer.toString(truncLen));
        // Inner SHA512 wrapped as a MessageDigest child
        INode inner = n.getChildren().get(MessageDigest.class);
        assertThat(inner).isNotNull().isInstanceOf(SHA2.class);
        assertThat(inner.asString()).isEqualTo("SHA-512");
    }

    private static void assertShake(List<INode> nodes, String asString, int pset) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(SHAKE.class);
        assertThat(n.getKind()).isEqualTo(ExtendableOutputFunction.class);
        assertThat(n.asString()).isEqualTo(asString);
        INode psetNode = n.getChildren().get(ParameterSetIdentifier.class);
        assertThat(psetNode).isNotNull();
        assertThat(psetNode.asString()).isEqualTo(Integer.toString(pset));
    }
}
