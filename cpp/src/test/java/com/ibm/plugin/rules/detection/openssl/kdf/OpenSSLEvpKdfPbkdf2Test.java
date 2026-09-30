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
package com.ibm.plugin.rules.detection.openssl.kdf;

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

class OpenSSLEvpKdfPbkdf2Test extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 4: PKCS5_PBKDF2_HMAC(pass, 8, salt, 16, 10000, EVP_sha256(), 32, out);
                    finding(
                            "KeyDerivationFunctionContext{ValueAction:PBKDF2-HMAC}[KeyDerivationFunctionContext{SaltSize:128}, "
                                    + "KeyDerivationFunctionContext{IterationCount:10000}, "
                                    + "KeyDerivationFunctionContext{KeySize:256}, "
                                    + "DigestContext{ValueAction:SHA-256}]",
                            "PasswordBasedKeyDerivationFunction:PBKDF2-SHA-256[KeyDerivation:KEYDERIVATION, "
                                    + "KeyLength:256, MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], NumberOfIterations:10000, "
                                    + "SaltLength:128]"),
                    // 8: PKCS5_PBKDF2_HMAC_SHA1(pass, 8, salt, 16, 2048, 20, out);
                    finding(
                            "KeyDerivationFunctionContext{ValueAction:PBKDF2-HMAC-SHA1}[KeyDerivationFunctionContext{SaltSize:128}, "
                                    + "KeyDerivationFunctionContext{IterationCount:2048}, "
                                    + "KeyDerivationFunctionContext{KeySize:160}]",
                            "PasswordBasedKeyDerivationFunction:PBKDF2-SHA-1[KeyDerivation:KEYDERIVATION, "
                                    + "KeyLength:160, MessageDigest:SHA-1[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:160, Oid:1.3.14.3.2.26], NumberOfIterations:2048, SaltLength:128]"));

    private int findings = 0;

    OpenSSLEvpKdfPbkdf2Test() {
        super(OpenSSLEvpKdfPbkdf2.rules());
    }

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/kdf/OpenSSLEvpKdfPbkdf2TestFile.cc", this);
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
