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
import com.ibm.engine.model.context.DigestContext;
import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.StreamCipher;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.Aria;
import com.ibm.mapper.model.algorithms.Blowfish;
import com.ibm.mapper.model.algorithms.Camellia;
import com.ibm.mapper.model.algorithms.ChaCha20;
import com.ibm.mapper.model.algorithms.ChaCha20Poly1305;
import com.ibm.mapper.model.algorithms.DES;
import com.ibm.mapper.model.algorithms.DESede;
import com.ibm.mapper.model.algorithms.IDEA;
import com.ibm.mapper.model.algorithms.RC2;
import com.ibm.mapper.model.algorithms.RC4;
import com.ibm.mapper.model.algorithms.RC5;
import com.ibm.mapper.model.algorithms.SEED;
import com.ibm.mapper.model.algorithms.SM4;
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
 * Covers EVP cipher detection rules in {@link OpenSSLEvpCipher}.
 *
 * <p>Follows the deep-assert pattern documented in {@link
 * com.ibm.plugin.rules.detection.openssl.rand.OpenSSLRandTest}.
 *
 * <p>Dispatches on detection value string and verifies INode shape per family (AES, ARIA, Camellia,
 * SM4, DES/DESede, Blowfish, CAST5, RC2, RC4, RC5, IDEA, SEED, ChaCha20, ChaCha20-Poly1305, NULL,
 * plus EVP/CMS/PKCS7 init/fetch/misc operations).
 */
class OpenSSLEvpCipherTest extends TestBase {

    private int findingCount = 0;
    private final Set<String> observed = new HashSet<>();

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/cipher/OpenSSLEvpCipherTestFile.cc", this);
        assertThat(findingCount).isEqualTo(199);
        assertThat(observed).hasSize(179);
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
        IValue<AstNode> value = detectionStore.getDetectionValues().get(0);

        // EVP_PKEY_CTX_set_rsa_oaep_md's md argument is traced back to its constructing call
        // (see OpenSSLEvpMessageDigest); set_rsa_oaep_md_name resolves its own name string
        // directly. Both surface here as their own DigestContext entry.
        if (detectionStore.getDetectionValueContext() instanceof DigestContext) {
            observed.add(value.asString());
            findingCount++;
            assertThat(value.asString()).isEqualTo("SHA-256");
            INode n = head(nodes);
            assertThat(n).isInstanceOf(MessageDigest.class);
            return;
        }

        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        observed.add(value.asString());
        findingCount++;

        String v = value.asString();
        if (v.equals("NULL")) {
            assertThat(nodes).isEmpty();
            return;
        }
        if (v.startsWith("AES-")
                && (v.contains("-CBC-HMAC-SHA1") || v.contains("-CBC-HMAC-SHA256"))) {
            assertAesHmac(nodes, v);
            return;
        }
        if (v.startsWith("AES-")) {
            assertAesGeneric(nodes, v);
            return;
        }
        if (v.startsWith("ARIA-")) {
            assertSizedFamily(nodes, v, Aria.class);
            return;
        }
        if (v.startsWith("CAMELLIA-")) {
            assertSizedFamily(nodes, v, Camellia.class);
            return;
        }
        if (v.startsWith("SM4-")) {
            assertSm4(nodes, v.substring("SM4-".length()));
            return;
        }
        if (v.equals("DESX-CBC")) {
            assertDes(nodes, "CBC");
            return;
        }
        if (v.equals("DES-EDE3-WRAP")) {
            assertThat(nodes).isNotNull();
            return;
        }
        if (v.startsWith("DESede3")) {
            assertDesede(nodes, v, 168);
            return;
        }
        if (v.equals("DESede") || v.startsWith("DESede-")) {
            assertDesede(nodes, v, 112);
            return;
        }
        if (v.startsWith("DES-")) {
            String mode = v.substring(4);
            assertDes(nodes, mode);
            return;
        }
        if (v.startsWith("BLOWFISH-")) {
            assertBlowfish(nodes, v.substring("BLOWFISH-".length()));
            return;
        }
        if (v.startsWith("CAST5-")) {
            assertCast(nodes, v.substring("CAST5-".length()));
            return;
        }
        if (v.startsWith("RC2-")) {
            assertRc2(nodes, v);
            return;
        }
        if (v.equals("RC4")) {
            INode n = head(nodes);
            assertThat(n).isInstanceOf(RC4.class);
            assertThat(n.getKind()).isEqualTo(StreamCipher.class);
            return;
        }
        if (v.equals("RC4-40")) {
            INode n = head(nodes);
            assertThat(n).isInstanceOf(RC4.class);
            INode kl = n.getChildren().get(KeyLength.class);
            assertThat(kl).isNotNull();
            assertThat(kl.asString()).isEqualTo("40");
            return;
        }
        if (v.equals("RC4-HMAC-MD5")) {
            INode n = head(nodes);
            assertThat(n).isInstanceOf(RC4.class);
            return;
        }
        if (v.startsWith("RC5-")) {
            assertRc5(nodes, v.substring("RC5-".length()));
            return;
        }
        if (v.startsWith("IDEA-")) {
            assertIdea(nodes, v.substring("IDEA-".length()));
            return;
        }
        if (v.startsWith("SEED-")) {
            assertSeed(nodes, v.substring("SEED-".length()));
            return;
        }
        if (v.equals("ChaCha20")) {
            INode n = head(nodes);
            assertThat(n).isInstanceOf(ChaCha20.class);
            assertThat(n.getKind()).isEqualTo(StreamCipher.class);
            return;
        }
        if (v.equals("ChaCha20-Poly1305")) {
            INode n = head(nodes);
            assertThat(n).isInstanceOf(ChaCha20Poly1305.class);
            assertThat(n.getKind()).isEqualTo(AuthenticatedEncryption.class);
            return;
        }
        if (v.equals("ENCRYPT")
                || v.equals("DECRYPT")
                || v.equals("CIPHER-INIT")
                || v.equals("RSA-PADDING")
                || v.equals("RSA-OAEP-LABEL")
                || v.equals("CMS-ENCRYPT")
                || v.equals("CMS-ENVELOPED-DATA")
                || v.equals("CMS-AUTH-ENVELOPED-DATA")
                || v.equals("CMS-ENCRYPTED-DATA")
                || v.equals("CMS-ENCRYPTED-DATA-KEY")
                || v.equals("CMS-RECIPIENT-KEY")
                || v.equals("PKCS7-ENCRYPT")
                || v.equals("PKCS7-CIPHER")) {
            assertThat(nodes).isNotNull();
            return;
        }
        // EVP_ASYM_CIPHER_fetch(NULL, "RSA", NULL): real algorithm name resolved via
        // AlgorithmFactory, but CxxCipherContextTranslator has no RSA case, so it resolves to
        // nothing. EVP_get_cipherbyname("AES-256-GCM") is handled above by the AES- branch.
        if (v.equals("RSA")) {
            assertThat(nodes).isEmpty();
            return;
        }
        throw new AssertionError("Unexpected value: " + v);
    }

    /* ============================ helpers ============================ */

    private static INode head(List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        return nodes.get(0);
    }

    private static String aesOidFor(int keyLen) {
        return switch (keyLen) {
            case 128 -> "2.16.840.1.101.3.4.1";
            case 192 -> "2.16.840.1.101.3.4.1.2";
            case 256 -> "2.16.840.1.101.3.4.1.4";
            default -> throw new AssertionError("Unknown AES key length: " + keyLen);
        };
    }

    private static void assertAesGeneric(List<INode> nodes, String v) {
        // AES-<keysize>-<mode...>
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
        assertThat(oid.asString()).isEqualTo(aesOidFor(keyLen));
    }

    private static void assertAesHmac(List<INode> nodes, String v) {
        // Same as generic AES — translator emits a single AES node with a composite Mode
        // (e.g. "CBC-HMAC-SHA1"), no separate HMAC subtree.
        assertAesGeneric(nodes, v);
    }

    private static void assertSizedFamily(
            List<INode> nodes, String v, Class<? extends INode> klass) {
        // <NAME>-<keysize>-<mode>
        String[] parts = v.split("-", 3);
        int keyLen = Integer.parseInt(parts[1]);
        String mode = parts[2];
        INode n = head(nodes);
        assertThat(n).isInstanceOf(klass);
        assertThat(n.getKind()).isEqualTo(BlockCipher.class);
        INode kl = n.getChildren().get(KeyLength.class);
        assertThat(kl).isNotNull();
        assertThat(kl.asString()).isEqualTo(Integer.toString(keyLen));
        INode m = n.getChildren().get(Mode.class);
        assertThat(m).isNotNull();
        assertThat(m.asString()).isEqualTo(mode);
    }

    private static void assertSm4(List<INode> nodes, String mode) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(SM4.class);
        assertThat(n.getKind()).isEqualTo(BlockCipher.class);
        INode m = n.getChildren().get(Mode.class);
        assertThat(m).isNotNull();
        assertThat(m.asString()).isEqualTo(mode);
    }

    private static void assertDes(List<INode> nodes, String mode) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(DES.class);
        assertThat(n.getKind()).isEqualTo(BlockCipher.class);
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

    private static void assertDesede(List<INode> nodes, String v, int keyLen) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(DESede.class);
        assertThat(n.getKind()).isEqualTo(BlockCipher.class);
        INode kl = n.getChildren().get(KeyLength.class);
        assertThat(kl).isNotNull();
        assertThat(kl.asString()).isEqualTo(Integer.toString(keyLen));
        INode bs = n.getChildren().get(BlockSize.class);
        assertThat(bs).isNotNull();
        assertThat(bs.asString()).isEqualTo("64");
        // mode optional (DESede / DESede3 bare have no mode)
        if (v.contains("-")) {
            INode m = n.getChildren().get(Mode.class);
            assertThat(m).isNotNull();
        }
    }

    private static void assertCast(List<INode> nodes, String mode) {
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

    private static void assertRc2(List<INode> nodes, String v) {
        // RC2-ECB / RC2-CBC / RC2-CFB / RC2-CFB64 / RC2-OFB → keyLen 128
        // RC2-40-CBC / RC2-64-CBC → keyLen 40 / 64
        INode n = head(nodes);
        assertThat(n).isInstanceOf(RC2.class);
        assertThat(n.getKind()).isEqualTo(BlockCipher.class);
        int expectedKeyLen;
        String expectedMode;
        if (v.equals("RC2-40-CBC")) {
            expectedKeyLen = 40;
            expectedMode = "CBC";
        } else if (v.equals("RC2-64-CBC")) {
            expectedKeyLen = 64;
            expectedMode = "CBC";
        } else {
            expectedKeyLen = 128;
            expectedMode = v.substring("RC2-".length());
        }
        INode kl = n.getChildren().get(KeyLength.class);
        assertThat(kl).isNotNull();
        assertThat(kl.asString()).isEqualTo(Integer.toString(expectedKeyLen));
        INode m = n.getChildren().get(Mode.class);
        assertThat(m).isNotNull();
        assertThat(m.asString()).isEqualTo(expectedMode);
    }

    private static void assertRc5(List<INode> nodes, String mode) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(RC5.class);
        assertThat(n.getKind()).isEqualTo(BlockCipher.class);
        INode kl = n.getChildren().get(KeyLength.class);
        assertThat(kl).isNotNull();
        assertThat(kl.asString()).isEqualTo("128");
        INode m = n.getChildren().get(Mode.class);
        assertThat(m).isNotNull();
        assertThat(m.asString()).isEqualTo(mode);
    }

    private static void assertIdea(List<INode> nodes, String mode) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(IDEA.class);
        assertThat(n.getKind()).isEqualTo(BlockCipher.class);
        INode m = n.getChildren().get(Mode.class);
        assertThat(m).isNotNull();
        assertThat(m.asString()).isEqualTo(mode);
    }

    private static void assertBlowfish(List<INode> nodes, String mode) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(Blowfish.class);
        assertThat(n.getKind()).isEqualTo(BlockCipher.class);
        INode kl = n.getChildren().get(KeyLength.class);
        assertThat(kl).isNotNull();
        assertThat(kl.asString()).isEqualTo("128");
        INode m = n.getChildren().get(Mode.class);
        assertThat(m).isNotNull();
        assertThat(m.asString()).isEqualTo(mode);
    }

    private static void assertSeed(List<INode> nodes, String mode) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(SEED.class);
        assertThat(n.getKind()).isEqualTo(BlockCipher.class);
        INode m = n.getChildren().get(Mode.class);
        assertThat(m).isNotNull();
        assertThat(m.asString()).isEqualTo(mode);
    }
}
