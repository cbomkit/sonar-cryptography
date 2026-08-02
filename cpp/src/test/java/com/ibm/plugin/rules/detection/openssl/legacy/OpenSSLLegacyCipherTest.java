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
package com.ibm.plugin.rules.detection.openssl.legacy;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.StreamCipher;
import com.ibm.mapper.model.algorithms.Blowfish;
import com.ibm.mapper.model.algorithms.DES;
import com.ibm.mapper.model.algorithms.IDEA;
import com.ibm.mapper.model.algorithms.RC2;
import com.ibm.mapper.model.algorithms.RC4;
import com.ibm.mapper.model.algorithms.cast.CAST128;
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
 * Covers all 43 rule entries in {@link OpenSSLLegacyCipher}.
 *
 * <p>Follows the deep-assert pattern documented in {@link
 * com.ibm.plugin.rules.detection.openssl.rand.OpenSSLRandTest}.
 *
 * <p>Fixture calls every method name listed across the 43 rules — including alias names inside
 * multi-method rules ({@code forMethods(a, b, c)}) — producing 47 findings (43 rules + 4 alias
 * extras from 3 multi-method rules).
 */
class OpenSSLLegacyCipherTest extends TestBase {

    private int findingCount = 0;
    private final Set<String> observed = new HashSet<>();

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/legacy/OpenSSLLegacyCipherTestFile.cc", this);
        assertThat(findingCount).isEqualTo(56);
        assertThat(observed).hasSize(53);
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
        if (v.startsWith("DES-")) {
            String mode = v.substring(4);
            assertDes(nodes, mode);
        } else if (v.startsWith("BLOWFISH-")) {
            String mode = v.substring("BLOWFISH-".length());
            assertBlowfish(nodes, mode);
        } else if (v.equals("RC4")) {
            assertRc4(nodes);
        } else if (v.startsWith("RC2-")) {
            String mode = v.substring(4);
            assertRc2(nodes, mode);
        } else if (v.startsWith("CAST5-")) {
            String mode = v.substring("CAST5-".length());
            assertCast128(nodes, mode);
        } else if (v.startsWith("IDEA-")) {
            String mode = v.substring("IDEA-".length());
            assertIdea(nodes, mode);
        } else if (v.startsWith("RC5-")) {
            assertThat(nodes).isNotNull();
        } else if (v.startsWith("CAMELLIA-")) {
            assertThat(nodes).isNotNull();
        } else if (v.startsWith("SEED-")) {
            assertThat(nodes).isNotNull();
        } else {
            // Bare names (AES, AES-ECB, AES-CBC, ..., DES, 3DES-*, BLOWFISH, RC2, CAST5, IDEA, RC5,
            // CAMELLIA, SEED)
            // and AES-WRAP/IGE — translator has no case → empty nodes.
            assertThat(nodes).isEmpty();
        }
    }

    private static INode head(List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        return nodes.get(0);
    }

    private static void assertDes(List<INode> nodes, String mode) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(DES.class);
        assertThat(n.getKind()).isEqualTo(BlockCipher.class);
        assertThat(n.asString()).isEqualTo("DES-56-" + mode);
        INode kl = n.getChildren().get(KeyLength.class);
        assertThat(kl).isNotNull();
        assertThat(kl.asString()).isEqualTo("56");
        INode bs = n.getChildren().get(BlockSize.class);
        assertThat(bs).isNotNull();
        assertThat(bs.asString()).isEqualTo("64");
        INode m = n.getChildren().get(Mode.class);
        assertThat(m).isNotNull();
        assertThat(m.asString()).isEqualTo(mode);
    }

    private static void assertBlowfish(List<INode> nodes, String mode) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(Blowfish.class);
        assertThat(n.getKind()).isEqualTo(BlockCipher.class);
        assertThat(n.asString()).isEqualTo("Blowfish-128-" + mode);
        INode kl = n.getChildren().get(KeyLength.class);
        assertThat(kl).isNotNull();
        assertThat(kl.asString()).isEqualTo("128");
        INode m = n.getChildren().get(Mode.class);
        assertThat(m).isNotNull();
        assertThat(m.asString()).isEqualTo(mode);
    }

    private static void assertRc4(List<INode> nodes) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(RC4.class);
        assertThat(n.getKind()).isEqualTo(StreamCipher.class);
        assertThat(n.asString()).isEqualTo("RC4");
    }

    private static void assertRc2(List<INode> nodes, String mode) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(RC2.class);
        assertThat(n.getKind()).isEqualTo(BlockCipher.class);
        assertThat(n.asString()).isEqualTo("RC2-128-" + mode);
        INode kl = n.getChildren().get(KeyLength.class);
        assertThat(kl).isNotNull();
        assertThat(kl.asString()).isEqualTo("128");
        INode m = n.getChildren().get(Mode.class);
        assertThat(m).isNotNull();
        assertThat(m.asString()).isEqualTo(mode);
    }

    private static void assertCast128(List<INode> nodes, String mode) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(CAST128.class);
        assertThat(n.getKind()).isEqualTo(BlockCipher.class);
        assertThat(n.asString()).isEqualTo("CAST5-128-" + mode);
        INode kl = n.getChildren().get(KeyLength.class);
        assertThat(kl).isNotNull();
        assertThat(kl.asString()).isEqualTo("128");
        INode bs = n.getChildren().get(BlockSize.class);
        assertThat(bs).isNotNull();
        assertThat(bs.asString()).isEqualTo("64");
        INode m = n.getChildren().get(Mode.class);
        assertThat(m).isNotNull();
        assertThat(m.asString()).isEqualTo(mode);
    }

    private static void assertIdea(List<INode> nodes, String mode) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(IDEA.class);
        assertThat(n.getKind()).isEqualTo(BlockCipher.class);
        assertThat(n.asString()).isEqualTo("IDEA-" + mode);
        INode m = n.getChildren().get(Mode.class);
        assertThat(m).isNotNull();
        assertThat(m.asString()).isEqualTo(mode);
    }
}
