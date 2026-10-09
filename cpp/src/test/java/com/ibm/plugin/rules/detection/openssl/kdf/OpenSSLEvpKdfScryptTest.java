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
import com.ibm.engine.rule.RuleSets;
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

class OpenSSLEvpKdfScryptTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 4: EVP_PBE_scrypt(pass, 8, salt, 16, 16384, 8, 1, 0, key, 32);
                    finding(
                            "KeyDerivationFunctionContext{ValueAction:SCRYPT}[KeyDerivationFunctionContext{SaltSize:128}, "
                                    + "KeyDerivationFunctionContext{KeySize:256}]",
                            "PasswordBasedKeyDerivationFunction:scrypt[KeyDerivation:KEYDERIVATION, "
                                    + "KeyLength:256, SaltLength:128]"),
                    // 8: EVP_PBE_scrypt_ex(pass, 8, salt, 32, 1048576, 8, 1, 0, key, 64, NULL,
                    // NULL);
                    finding(
                            "KeyDerivationFunctionContext{ValueAction:SCRYPT}[KeyDerivationFunctionContext{SaltSize:256}, "
                                    + "KeyDerivationFunctionContext{KeySize:512}]",
                            "PasswordBasedKeyDerivationFunction:scrypt[KeyDerivation:KEYDERIVATION, "
                                    + "KeyLength:512, SaltLength:256]"));

    private int findings = 0;

    OpenSSLEvpKdfScryptTest() {
        super(RuleSets.rulesOf(OpenSSLEvpKdfScrypt.class));
    }

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/kdf/OpenSSLEvpKdfScryptTestFile.cc", this);
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
