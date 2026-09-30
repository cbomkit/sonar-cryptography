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
package com.ibm.plugin.rules.detection.openssl.keyagreement;

import static com.ibm.plugin.ExpectedFinding.assertAllReported;
import static com.ibm.plugin.ExpectedFinding.assertFinding;
import static com.ibm.plugin.ExpectedFinding.finding;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.CxxVerifier;
import com.ibm.plugin.ExpectedFinding;
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
 * The key exchange, KEM and HPKE suite selections of {@link OpenSSLEvpKeyAgreement} are reported,
 * while the derivation and encapsulation calls, whose key type is not known at the call, and a KDF
 * type of "none" are not. The KDFs and HPKE suite forms are covered by {@link
 * OpenSSLKeyAgreementKdfTest}.
 */
class OpenSSLEvpKeyAgreementTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 25: EVP_KEYEXCH_fetch(NULL, "ECDH", NULL);
                    finding(
                            "KeyAgreementContext{Algorithm:ECDH}",
                            "KeyAgreement:ECDH[Oid:1.3.132.1.12]"),
                    // 26: EVP_KEM_fetch(NULL, "RSA", NULL);
                    finding(
                            "KeyAgreementContext{Algorithm:RSA}",
                            "KeyEncapsulationMechanism:RSASVE"),
                    // 39: OSSL_HPKE_str2suite("X25519,HKDF-SHA256,AES-128-GCM", NULL);
                    finding(
                            "KeyAgreementContext{ValueAction:X25519,HKDF-SHA256,AES-128-GCM}",
                            "PublicKeyEncryption:HPKE[AuthenticatedEncryption:AES-128-GCM[BlockSize:128, "
                                    + "KeyLength:128, Mode:GCM, Oid:2.16.840.1.101.3.4.1.6], "
                                    + "KeyDerivationFunction:HKDF-SHA-256[MessageDigest:SHA-256[BlockSize:512, "
                                    + "Digest:DIGEST, DigestSize:256, Oid:2.16.840.1.101.3.4.2.1]], "
                                    + "KeyEncapsulationMechanism:DHKEM[KeyAgreement:x25519[EllipticCurve:Curve25519, "
                                    + "Oid:1.3.101.110]]]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify(
                "rules/detection/openssl/keyagreement/OpenSSLEvpKeyAgreementTestFile.cc", this);
        assertAllReported(FINDINGS, findings);
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
        findings++;
        assertFinding(FINDINGS, findingId, detectionStore, nodes);
    }
}
