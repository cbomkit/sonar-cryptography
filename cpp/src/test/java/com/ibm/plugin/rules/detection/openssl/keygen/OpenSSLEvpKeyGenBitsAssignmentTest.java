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
 * A variable gives a key size its initial value and the values of the plain assignments to the
 * variable itself, and an element of an array the values assigned to that element. A compound
 * assignment, an assignment to another element, to another array indexed by the variable, or
 * through a pointer to it does not assign the variable a value.
 */
class OpenSSLEvpKeyGenBitsAssignmentTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 7: EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
                    finding(
                            "KeyContext{ValueAction:RSA}[KeyContext{KeySize:2048}]",
                            "PublicKeyEncryption:RSA-2048[KeyLength:2048, Oid:1.2.840.113549.1.1.1]"),
                    // 15: EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
                    finding(
                            "KeyContext{ValueAction:RSA}[KeyContext{KeySize:3072}]",
                            "PublicKeyEncryption:RSA-3072[KeyLength:3072, Oid:1.2.840.113549.1.1.1]"),
                    // 23: EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
                    finding(
                            "KeyContext{ValueAction:RSA}[KeyContext{KeySize:4096}]",
                            "PublicKeyEncryption:RSA-4096[KeyLength:4096, Oid:1.2.840.113549.1.1.1]"),
                    // 31: EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
                    finding(
                            "KeyContext{ValueAction:RSA}[KeyContext{KeySize:2048}]",
                            "PublicKeyEncryption:RSA-2048[KeyLength:2048, Oid:1.2.840.113549.1.1.1]"),
                    // 38: EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
                    finding(
                            "KeyContext{ValueAction:RSA}[KeyContext{KeySize:1024, KeySize:4096}]",
                            "PublicKeyEncryption:RSA-1024[KeyLength:1024, Oid:1.2.840.113549.1.1.1]",
                            "PublicKeyEncryption:RSA-4096[KeyLength:4096, Oid:1.2.840.113549.1.1.1]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify(
                "rules/detection/openssl/keygen/OpenSSLEvpKeyGenBitsAssignmentTestFile.cc", this);
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
