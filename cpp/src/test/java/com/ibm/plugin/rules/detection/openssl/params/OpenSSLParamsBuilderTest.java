/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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
package com.ibm.plugin.rules.detection.openssl.params;

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
 * The digest and cipher entries of the parameters built with an {@code OSSL_PARAM_BLD}, pushed with
 * {@code OSSL_PARAM_BLD_push_utf8_string} or {@code OSSL_PARAM_BLD_push_utf8_ptr}, are reported
 * with the KDF or MAC the built parameters are set on, as the entries of an {@code OSSL_PARAM}
 * array are.
 */
class OpenSSLParamsBuilderTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 7: EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
                    finding(
                            "KeyDerivationFunctionContext{Algorithm:HKDF}[KeyDerivationFunctionContext{}[KeyDerivationFunctionContext{KeySize:256}[DigestContext{}[DigestContext{Algorithm:SHA-1}]]]]",
                            "KeyDerivationFunction:HKDF-SHA-1[KeyDerivation:KEYDERIVATION, "
                                    + "KeyLength:256, MessageDigest:SHA-1[BlockSize:512, "
                                    + "Digest:DIGEST, DigestSize:160, Oid:1.3.14.3.2.26]]"),
                    // 17: EVP_MAC *mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
                    finding(
                            "MacContext{Algorithm:CMAC}[MacContext{}[MacContext{}[CipherContext{}[CipherContext{Algorithm:AES-128-CBC}]]]]",
                            "Mac:CMAC-AES[BlockCipher:AES-128-CBC[BlockSize:128, KeyLength:128, "
                                    + "Mode:CBC, Oid:2.16.840.1.101.3.4.1.2], Tag:TAG]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/params/OpenSSLParamsBuilderTestFile.cc", this);
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
