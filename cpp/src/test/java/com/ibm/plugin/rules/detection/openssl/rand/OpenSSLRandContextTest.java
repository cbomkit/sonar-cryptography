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
 * A DRBG fetched by name gets the cipher or digest that is set on the context created from it,
 * whether it is passed to {@code EVP_RAND_CTX_set_params} or to {@code EVP_RAND_instantiate}.
 */
class OpenSSLRandContextTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 5: EVP_RAND *rand = EVP_RAND_fetch(NULL, "CTR-DRBG", NULL);
                    finding(
                            "PRNGContext{Algorithm:CTR-DRBG}[PRNGContext{}[PRNGContext{}[CipherContext{Algorithm:AES-256-CTR}]]]",
                            "PseudorandomNumberGenerator:CTR_DRBG-AES-256[BlockCipher:AES-256-CTR[BlockSize:128, "
                                    + "KeyLength:256, Mode:CTR, Oid:2.16.840.1.101.3.4.1.4]]"),
                    // 15: EVP_RAND *rand = EVP_RAND_fetch(NULL, "hmac-drbg", NULL);
                    finding(
                            "PRNGContext{Algorithm:hmac-drbg}[PRNGContext{}[PRNGContext{}[DigestContext{Algorithm:SHA-256}]]]",
                            "PseudorandomNumberGenerator:HMAC_DRBG-SHA-256[MessageDigest:SHA-256[BlockSize:512, "
                                    + "Digest:DIGEST, DigestSize:256, Oid:2.16.840.1.101.3.4.2.1]]"),
                    // 25: EVP_RAND_fetch(NULL, "SEED-SRC", NULL);
                    finding(
                            "PRNGContext{Algorithm:SEED-SRC}",
                            "PseudorandomNumberGenerator:SEED-SRC"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/rand/OpenSSLRandContextTestFile.cc", this);
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
