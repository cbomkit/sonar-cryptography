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
package com.ibm.plugin.rules.detection.openssl.keygen;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.KeyEncapsulationMechanism;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.ParameterSetIdentifier;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.DH;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.ECDSA;
import com.ibm.mapper.model.algorithms.Ed25519;
import com.ibm.mapper.model.algorithms.Ed448;
import com.ibm.mapper.model.algorithms.MLDSA;
import com.ibm.mapper.model.algorithms.MLKEM;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.SM2;
import com.ibm.mapper.model.algorithms.SPHINCSPlus;
import com.ibm.mapper.model.algorithms.SecP256r1MLKEM768;
import com.ibm.mapper.model.algorithms.SecP384r1MLKEM1024;
import com.ibm.mapper.model.algorithms.X25519;
import com.ibm.mapper.model.algorithms.X25519MLKEM768;
import com.ibm.mapper.model.algorithms.X448;
import com.ibm.mapper.model.algorithms.X448MLKEM1024;
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
 * Covers all rule entries in {@link OpenSSLEvpKeyGen}.
 *
 * <p>Follows the deep-assert pattern documented in {@link
 * com.ibm.plugin.rules.detection.openssl.rand.OpenSSLRandTest}.
 */
class OpenSSLEvpKeyGenTest extends TestBase {

    private int findingCount = 0;
    private final Set<String> observed = new HashSet<>();

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/keygen/OpenSSLEvpKeyGenTestFile.cc", this);
        // findingCount includes the p256_nid/rsa_bits local-variable calls (resolved via
        // CxxSymbolResolverVisitor); observed stays the same size since both resolve to values
        // ("EC-P256", "RSA-2048") already produced by their literal counterparts.
        assertThat(findingCount).isEqualTo(21);
        assertThat(observed).hasSize(13);
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

        // EVP_PKEY_CTX_set_dsa_paramgen_md_props("SHA256", ...) resolves through DigestContext
        // (see OpenSSLEvpKeyGen.java).
        if (detectionStore.getDetectionValueContext() instanceof DigestContext) {
            observed.add(value.asString());
            assertThat(value.asString()).isEqualTo("SHA-256");
            assertThat(nodes).isNotEmpty();
            findingCount++;
            return;
        }

        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        observed.add(value.asString());

        switch (value.asString()) {
            case "RSA", "RSA-PSS" -> assertRsaBare(nodes);
            case "DSA" -> assertSimpleSig(nodes, DSA.class, "DSA", "1.2.840.10040.4.1");
            case "EC" -> assertEcdsa(nodes);
            case "DH" -> assertDh(nodes);
            case "ED25519" -> assertEd25519(nodes);
            case "ED448" -> assertEd448(nodes);
            case "X25519" ->
                    assertEdwardsKa(nodes, X25519.class, "x25519", "Curve25519", "1.3.101.110");
            case "X448" -> assertEdwardsKa(nodes, X448.class, "x448", "Curve448", "1.3.101.111");
            case "ML-KEM-512" ->
                    assertKemPset(nodes, MLKEM.class, "ML-KEM-512", "2.16.840.1.101.3.4.4.1", 512);
            case "ML-KEM-768" ->
                    assertKemPset(nodes, MLKEM.class, "ML-KEM-768", "2.16.840.1.101.3.4.4.2", 768);
            case "ML-KEM-1024" ->
                    assertKemPset(
                            nodes, MLKEM.class, "ML-KEM-1024", "2.16.840.1.101.3.4.4.3", 1024);
            case "X25519MLKEM768" -> assertHybridKem(nodes, X25519MLKEM768.class, "X25519MLKEM768");
            case "X448MLKEM1024" -> assertHybridKem(nodes, X448MLKEM1024.class, "X448MLKEM1024");
            case "SecP256r1MLKEM768" ->
                    assertHybridKem(nodes, SecP256r1MLKEM768.class, "SecP256r1MLKEM768");
            case "SecP384r1MLKEM1024" ->
                    assertHybridKem(nodes, SecP384r1MLKEM1024.class, "SecP384r1MLKEM1024");
            case "ML-DSA-44" -> assertMldsa(nodes, "ML-DSA-44", "2.16.840.1.101.3.4.3.17", 44);
            case "ML-DSA-65" -> assertMldsa(nodes, "ML-DSA-65", "2.16.840.1.101.3.4.3.18", 65);
            case "ML-DSA-87" -> assertMldsa(nodes, "ML-DSA-87", "2.16.840.1.101.3.4.3.19", 87);
            case "SLH-DSA-SHA2-128F",
                    "SLH-DSA-SHA2-128S",
                    "SLH-DSA-SHAKE-128F",
                    "SLH-DSA-SHAKE-128S",
                    "SLH-DSA-SHA2-192F",
                    "SLH-DSA-SHA2-192S",
                    "SLH-DSA-SHAKE-192F",
                    "SLH-DSA-SHAKE-192S",
                    "SLH-DSA-SHA2-256F",
                    "SLH-DSA-SHA2-256S",
                    "SLH-DSA-SHAKE-256F",
                    "SLH-DSA-SHAKE-256S" ->
                    assertSlhdsa(nodes);
            case "SM2" -> {
                INode n = head(nodes);
                assertThat(n).isInstanceOf(SM2.class);
                assertThat(n.getKind()).isEqualTo(Signature.class);
            }
            case "DH-2048", "DH-4096" -> assertDh(nodes);
            case "DSA-2048", "DSA-3072" ->
                    assertSimpleSig(nodes, DSA.class, "DSA", "1.2.840.10040.4.1");
            case "EC-P256",
                    "EC-P384",
                    "EC-P521",
                    "EC-SECP256K1",
                    "EC-BRAINPOOLP256R1",
                    "EC-BRAINPOOLP384R1",
                    "EC-BRAINPOOLP512R1" ->
                    assertEcdsa(nodes);
            case "RSA-2048" -> assertRsaSized(nodes, 2048);
            case "RSA-3072" -> assertRsaSized(nodes, 3072);
            case "RSA-4096" -> assertRsaSized(nodes, 4096);
            case "KEYGEN", "KEYGEN-INIT", "PARAMGEN" -> assertThat(nodes).isEmpty();
            case "EC-PARAM-ENC",
                    "RSA-KEYGEN-PUBEXP",
                    "RSA-KEYGEN-PRIMES",
                    "DSA-PARAMGEN-Q-BITS",
                    "DSA-PARAMGEN-TYPE" ->
                    assertThat(nodes).isNotNull();
            default -> throw new AssertionError("Unexpected value: " + value.asString());
        }
        findingCount++;
    }

    /* helpers */

    private static INode head(List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        return nodes.get(0);
    }

    private static void assertRsaBare(List<INode> nodes) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(RSA.class);
        assertThat(n.getKind()).isEqualTo(PublicKeyEncryption.class);
        assertThat(n.asString()).isEqualTo("RSA");
        INode oid = n.getChildren().get(Oid.class);
        assertThat(oid).isNotNull();
        assertThat(oid.asString()).isEqualTo("1.2.840.113549.1.1.1");
    }

    private static void assertRsaSized(List<INode> nodes, int keyLength) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(RSA.class);
        assertThat(n.asString()).isEqualTo("RSA-" + keyLength);
        INode kl = n.getChildren().get(KeyLength.class);
        assertThat(kl).isNotNull();
        assertThat(kl.asString()).isEqualTo(Integer.toString(keyLength));
    }

    private static void assertSimpleSig(
            List<INode> nodes, Class<? extends INode> klass, String asString, String oid) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(klass);
        assertThat(n.getKind()).isEqualTo(Signature.class);
        assertThat(n.asString()).isEqualTo(asString);
        INode oidNode = n.getChildren().get(Oid.class);
        assertThat(oidNode).isNotNull();
        assertThat(oidNode.asString()).isEqualTo(oid);
    }

    private static void assertEcdsa(List<INode> nodes) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(ECDSA.class);
        assertThat(n.getKind()).isEqualTo(Signature.class);
    }

    private static void assertDh(List<INode> nodes) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(DH.class);
        assertThat(n.getKind()).isEqualTo(PublicKeyEncryption.class);
        assertThat(n.asString()).isEqualTo("DH");
        INode oid = n.getChildren().get(Oid.class);
        assertThat(oid).isNotNull();
        assertThat(oid.asString()).isEqualTo("1.2.840.113549.1.3.1");
    }

    private static void assertEd25519(List<INode> nodes) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(Ed25519.class);
        assertThat(n.getKind()).isEqualTo(Signature.class);
        assertThat(n.asString()).isEqualTo("Ed25519");
        INode curve = n.getChildren().get(EllipticCurve.class);
        assertThat(curve).isNotNull();
        assertThat(curve.asString()).isEqualTo("Edwards25519");
    }

    private static void assertEd448(List<INode> nodes) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(Ed448.class);
        assertThat(n.getKind()).isEqualTo(Signature.class);
        assertThat(n.asString()).isEqualTo("Ed448");
        INode curve = n.getChildren().get(EllipticCurve.class);
        assertThat(curve).isNotNull();
        assertThat(curve.asString()).isEqualTo("Edwards448");
    }

    private static void assertEdwardsKa(
            List<INode> nodes,
            Class<? extends INode> klass,
            String asString,
            String curveName,
            String oid) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(klass);
        assertThat(n.getKind()).isEqualTo(KeyAgreement.class);
        assertThat(n.asString()).isEqualTo(asString);
        INode curve = n.getChildren().get(EllipticCurve.class);
        assertThat(curve).isNotNull();
        assertThat(curve.asString()).isEqualTo(curveName);
        INode oidNode = n.getChildren().get(Oid.class);
        assertThat(oidNode).isNotNull();
        assertThat(oidNode.asString()).isEqualTo(oid);
    }

    private static void assertKemPset(
            List<INode> nodes,
            Class<? extends INode> klass,
            String asString,
            String oid,
            int pset) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(klass);
        assertThat(n.getKind()).isEqualTo(KeyEncapsulationMechanism.class);
        assertThat(n.asString()).isEqualTo(asString);
        INode oidNode = n.getChildren().get(Oid.class);
        assertThat(oidNode).isNotNull();
        assertThat(oidNode.asString()).isEqualTo(oid);
        INode psetNode = n.getChildren().get(ParameterSetIdentifier.class);
        assertThat(psetNode).isNotNull();
        assertThat(psetNode.asString()).isEqualTo(Integer.toString(pset));
    }

    private static void assertHybridKem(
            List<INode> nodes, Class<? extends INode> klass, String asString) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(klass);
        assertThat(n.getKind()).isEqualTo(KeyEncapsulationMechanism.class);
        assertThat(n.asString()).isEqualTo(asString);
    }

    private static void assertMldsa(List<INode> nodes, String asString, String oid, int pset) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(MLDSA.class);
        assertThat(n.getKind()).isEqualTo(Signature.class);
        assertThat(n.asString()).isEqualTo(asString);
        INode oidNode = n.getChildren().get(Oid.class);
        assertThat(oidNode).isNotNull();
        assertThat(oidNode.asString()).isEqualTo(oid);
        INode psetNode = n.getChildren().get(ParameterSetIdentifier.class);
        assertThat(psetNode).isNotNull();
        assertThat(psetNode.asString()).isEqualTo(Integer.toString(pset));
    }

    private static void assertSlhdsa(List<INode> nodes) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(SPHINCSPlus.class);
        assertThat(n.getKind()).isEqualTo(Signature.class);
        assertThat(n.asString()).isEqualTo("SLH-DSA");
    }
}
