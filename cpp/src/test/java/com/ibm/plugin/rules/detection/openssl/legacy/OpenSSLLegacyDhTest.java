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

/** Covers all rule entries in {@link OpenSSLLegacyDh}. */
class OpenSSLLegacyDhTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 9: DH_generate_key(dh);
                    finding(
                            "PrivateKeyContext{ValueAction:DH}[KeyContext{ValueAction:DH}[KeyContext{KeySize:2048}]]",
                            "PrivateKey:FFDH[KeyLength:2048, "
                                    + "PublicKeyEncryption:FFDH-2048[KeyGeneration:KEYGENERATION, "
                                    + "KeyLength:2048, Oid:1.2.840.113549.1.3.1]]"),
                    // 10: DH_get_1024_160();
                    finding(
                            "KeyContext{ValueAction:DH-1024-160}",
                            "PublicKeyEncryption:FFDH-1024[KeyLength:1024, Oid:1.2.840.113549.1.3.1]"),
                    // 11: DH_get_2048_224();
                    finding(
                            "KeyContext{ValueAction:DH-2048-224}",
                            "PublicKeyEncryption:FFDH-2048[KeyLength:2048, Oid:1.2.840.113549.1.3.1]"),
                    // 12: DH_get_2048_256();
                    finding(
                            "KeyContext{ValueAction:DH-2048-256}",
                            "PublicKeyEncryption:FFDH-2048[KeyLength:2048, Oid:1.2.840.113549.1.3.1]"),
                    // 13: DH_compute_key(secret, pub_key, dh);
                    finding(
                            "KeyAgreementContext{ValueAction:DH}",
                            "KeyAgreement:FFDH[Oid:1.2.840.113549.1.3.1]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/legacy/OpenSSLLegacyDhTestFile.cc", this);
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
