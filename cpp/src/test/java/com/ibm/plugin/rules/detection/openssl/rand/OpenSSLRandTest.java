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
 * Covers the rules in {@link com.ibm.plugin.rules.detection.openssl.rand.OpenSSLRand}: the random
 * bytes functions and the DRBGs fetched by name.
 *
 * <p>As the other detection rule tests of the module, it asserts each finding, by its id, against
 * the expected detection store and translation ({@link ExpectedFinding}), as the detection rule
 * tests of the Java module do.
 */
class OpenSSLRandTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 7: RAND_bytes(buf, 32);
                    finding("PRNGContext{ValueAction:RAND}", "PseudorandomNumberGenerator:RAND"),
                    // 8: RAND_priv_bytes(buf, 32);
                    finding("PRNGContext{ValueAction:RAND}", "PseudorandomNumberGenerator:RAND"),
                    // 9: RAND_bytes_ex(NULL, buf, 32, 0);
                    finding("PRNGContext{ValueAction:RAND}", "PseudorandomNumberGenerator:RAND"),
                    // 10: RAND_priv_bytes_ex(NULL, buf, 32, 0);
                    finding("PRNGContext{ValueAction:RAND}", "PseudorandomNumberGenerator:RAND"),
                    // 12: EVP_RAND_fetch(NULL, "CTR-DRBG", NULL);
                    finding(
                            "PRNGContext{Algorithm:CTR-DRBG}",
                            "PseudorandomNumberGenerator:CTR_DRBG"),
                    // 13: EVP_RAND_fetch(NULL, "HASH-DRBG", NULL);
                    finding(
                            "PRNGContext{Algorithm:HASH-DRBG}",
                            "PseudorandomNumberGenerator:Hash_DRBG"),
                    // 14: EVP_RAND_fetch(NULL, "HMAC-DRBG", NULL);
                    finding(
                            "PRNGContext{Algorithm:HMAC-DRBG}",
                            "PseudorandomNumberGenerator:HMAC_DRBG"),
                    // 15: EVP_RAND_fetch(NULL, "SEED-SRC", NULL);
                    finding(
                            "PRNGContext{Algorithm:SEED-SRC}",
                            "PseudorandomNumberGenerator:SEED-SRC"),
                    // 16: EVP_RAND_fetch(NULL, "JITTER", NULL);
                    finding("PRNGContext{Algorithm:JITTER}", "PseudorandomNumberGenerator:JITTER"),
                    // 17: EVP_RAND_fetch(NULL, "TEST-RAND", NULL);
                    finding(
                            "PRNGContext{Algorithm:TEST-RAND}",
                            "PseudorandomNumberGenerator:TEST-RAND"),
                    // 19: RAND_set_DRBG_type(NULL, "CTR-DRBG", NULL, NULL, NULL);
                    finding(
                            "PRNGContext{Algorithm:CTR-DRBG}",
                            "PseudorandomNumberGenerator:CTR_DRBG"),
                    // 20: RAND_set_seed_source_type(NULL, "SEED-SRC", NULL);
                    finding(
                            "PRNGContext{Algorithm:SEED-SRC}",
                            "PseudorandomNumberGenerator:SEED-SRC"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/rand/OpenSSLRandTestFile.cc", this);
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
