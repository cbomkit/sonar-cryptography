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
package com.ibm.plugin.rules.detection.openssl.cipher;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.Camellia;
import com.ibm.plugin.CxxVerifier;
import com.ibm.plugin.TestBase;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

/**
 * Covers all 33 algorithm values detected via {@code EVP_CIPHER_fetch}, both as string literals and
 * via a local variable holding one of those same values.
 *
 * <p>Follows the deep-assert pattern documented in {@link
 * com.ibm.plugin.rules.detection.openssl.rand.OpenSSLRandTest}.
 */
class OpenSSLEvpCipherFetchTest extends TestBase {

    private final Set<String> observed = new HashSet<>();
    private int findingCount = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/cipher/OpenSSLEvpCipherFetchTestFile.cc", this);
        assertThat(observed).hasSize(33);
        assertThat(findingCount).isEqualTo(34);
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
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<AstNode> value = detectionStore.getDetectionValues().get(0);
        observed.add(value.asString());
        findingCount++;

        String v = value.asString();
        if (v.startsWith("AES-")) {
            assertAes(nodes, v);
        } else if (v.startsWith("CAMELLIA-")) {
            assertCamellia(nodes, v);
        } else {
            throw new AssertionError("Unexpected value: " + v);
        }
    }

    /* helpers */

    private static INode head(List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        return nodes.get(0);
    }

    private static void assertAes(List<INode> nodes, String v) {
        // v: AES-<keysize>-<modeparts...>
        String[] parts = v.split("-", 3);
        int keyLen = Integer.parseInt(parts[1]);
        String mode = parts[2];

        INode n = head(nodes);
        assertThat(n).isInstanceOf(AES.class);
        assertThat(n.getKind()).isEqualTo(BlockCipher.class);
        assertThat(n.asString()).isEqualTo("AES-" + keyLen + "-" + mode);

        INode kl = n.getChildren().get(KeyLength.class);
        assertThat(kl).isNotNull();
        assertThat(kl.asString()).isEqualTo(Integer.toString(keyLen));

        INode bs = n.getChildren().get(BlockSize.class);
        assertThat(bs).isNotNull();
        assertThat(bs.asString()).isEqualTo("128");

        INode m = n.getChildren().get(Mode.class);
        assertThat(m).isNotNull();
        assertThat(m.asString()).isEqualTo(mode);

        INode oid = n.getChildren().get(Oid.class);
        assertThat(oid).isNotNull();
        // OID base 2.16.840.1.101.3.4.1 with optional .keysize-suffix
        String expectedOid =
                switch (keyLen) {
                    case 128 -> "2.16.840.1.101.3.4.1";
                    case 192 -> "2.16.840.1.101.3.4.1.2";
                    case 256 -> "2.16.840.1.101.3.4.1.4";
                    default -> throw new AssertionError("Unknown AES key length: " + keyLen);
                };
        assertThat(oid.asString()).isEqualTo(expectedOid);
    }

    private static void assertCamellia(List<INode> nodes, String v) {
        String[] parts = v.split("-", 3);
        int keyLen = Integer.parseInt(parts[1]);
        String mode = parts[2];

        INode n = head(nodes);
        assertThat(n).isInstanceOf(Camellia.class);
        assertThat(n.getKind()).isEqualTo(BlockCipher.class);
        assertThat(n.asString()).isEqualTo(v);

        INode kl = n.getChildren().get(KeyLength.class);
        assertThat(kl).isNotNull();
        assertThat(kl.asString()).isEqualTo(Integer.toString(keyLen));

        INode m = n.getChildren().get(Mode.class);
        assertThat(m).isNotNull();
        assertThat(m.asString()).isEqualTo(mode);
    }
}
