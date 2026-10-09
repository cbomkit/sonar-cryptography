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

/** Covers all rule entries in {@link OpenSSLLegacyEc}. */
class OpenSSLLegacyEcTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 18: EC_KEY_new_by_curve_name(415);
                    finding(
                            "KeyContext{ValueAction:EC-prime256v1}",
                            "PublicKeyEncryption:EC-secp256r1[EllipticCurve:secp256r1, "
                                    + "Oid:1.2.840.10045.2.1]"),
                    // 19: EC_KEY_new_by_curve_name_ex(NULL, NULL, 415);
                    finding(
                            "KeyContext{ValueAction:EC-prime256v1}",
                            "PublicKeyEncryption:EC-secp256r1[EllipticCurve:secp256r1, "
                                    + "Oid:1.2.840.10045.2.1]"),
                    // 20: EC_KEY_generate_key(key);
                    finding(
                            "PrivateKeyContext{ValueAction:EC}",
                            "PrivateKey:EC[PublicKeyEncryption:EC[KeyGeneration:KEYGENERATION, "
                                    + "Oid:1.2.840.10045.2.1]]"),
                    // 25: EC_KEY_new_by_curve_name(p256_nid);
                    finding(
                            "KeyContext{ValueAction:EC-prime256v1}",
                            "PublicKeyEncryption:EC-secp256r1[EllipticCurve:secp256r1, "
                                    + "Oid:1.2.840.10045.2.1]"),
                    // 29: EC_KEY_new_by_curve_name(CurveNid::P256);
                    finding(
                            "KeyContext{ValueAction:EC-prime256v1}",
                            "PublicKeyEncryption:EC-secp256r1[EllipticCurve:secp256r1, "
                                    + "Oid:1.2.840.10045.2.1]"),
                    // 31: ECDSA_sign(0, buf, 32, buf, &siglen, key);
                    finding("SignatureContext{ValueAction:ECDSA-SIGN}", "Signature:ECDSA"),
                    // 32: ECDSA_do_sign(buf, 32, key);
                    finding("SignatureContext{ValueAction:ECDSA-SIGN}", "Signature:ECDSA"),
                    // 33: ECDSA_sign_ex(0, buf, 32, buf, &siglen, bn, bn, key);
                    finding("SignatureContext{ValueAction:ECDSA-SIGN}", "Signature:ECDSA"),
                    // 34: ECDSA_do_sign_ex(buf, 32, bn, bn, key);
                    finding("SignatureContext{ValueAction:ECDSA-SIGN}", "Signature:ECDSA"),
                    // 36: EC_GROUP_new_by_curve_name(415);
                    finding(
                            "KeyContext{ValueAction:EC-prime256v1}",
                            "PublicKeyEncryption:EC-secp256r1[EllipticCurve:secp256r1, "
                                    + "Oid:1.2.840.10045.2.1]"),
                    // 37: EC_GROUP_new_by_curve_name_ex(NULL, NULL, 415);
                    finding(
                            "KeyContext{ValueAction:EC-prime256v1}",
                            "PublicKeyEncryption:EC-secp256r1[EllipticCurve:secp256r1, "
                                    + "Oid:1.2.840.10045.2.1]"),
                    // 38: EC_GROUP_new_curve_GFp(bn, bn, bn, ctx);
                    finding(
                            "KeyContext{ValueAction:EC}",
                            "PublicKeyEncryption:EC[Oid:1.2.840.10045.2.1]"),
                    // 39: EC_GROUP_new_curve_GF2m(bn, bn, bn, ctx);
                    finding(
                            "KeyContext{ValueAction:EC}",
                            "PublicKeyEncryption:EC[Oid:1.2.840.10045.2.1]"),
                    // 40: EC_GROUP_new_from_ecparameters(NULL);
                    finding(
                            "KeyContext{ValueAction:EC}",
                            "PublicKeyEncryption:EC[Oid:1.2.840.10045.2.1]"),
                    // 41: EC_GROUP_new_from_ecpkparameters(NULL);
                    finding(
                            "KeyContext{ValueAction:EC}",
                            "PublicKeyEncryption:EC[Oid:1.2.840.10045.2.1]"),
                    // 42: EC_GROUP_new_from_params(NULL, NULL, NULL);
                    finding(
                            "KeyContext{ValueAction:EC}",
                            "PublicKeyEncryption:EC[Oid:1.2.840.10045.2.1]"),
                    // 44: ECDH_compute_key(buf, sizeof(buf), pt, key, NULL);
                    finding(
                            "KeyAgreementContext{ValueAction:ECDH}",
                            "KeyAgreement:ECDH[Oid:1.3.132.1.12]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/legacy/OpenSSLLegacyEcTestFile.cc", this);
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
