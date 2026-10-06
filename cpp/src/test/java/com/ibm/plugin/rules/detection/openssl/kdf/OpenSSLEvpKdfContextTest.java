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

/**
 * A KDF fetched by name gets the digest that is set on the context created from it, whether the
 * digest is passed to {@code EVP_KDF_CTX_set_params} or to {@code EVP_KDF_derive}, and whether the
 * fetched KDF is held in a variable or passed directly to {@code EVP_KDF_CTX_new}. The length given
 * to {@code EVP_KDF_derive} is the length of the derived key.
 */
class OpenSSLEvpKdfContextTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 5: EVP_KDF *kdf = EVP_KDF_fetch(NULL, "hkdf", NULL);
                    finding(
                            "KeyDerivationFunctionContext{Algorithm:hkdf}[KeyDerivationFunctionContext{}[KeyDerivationFunctionContext{}[DigestContext{Algorithm:SHA-256}]]]",
                            "KeyDerivationFunction:HKDF-SHA-256[KeyDerivation:KEYDERIVATION, "
                                    + "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, DigestSize:256, "
                                    + "Oid:2.16.840.1.101.3.4.2.1]]"),
                    // 17: EVP_KDF *kdf = EVP_KDF_fetch(NULL, name, NULL);
                    finding(
                            "KeyDerivationFunctionContext{Algorithm:PBKDF2}[KeyDerivationFunctionContext{}[KeyDerivationFunctionContext{}[DigestContext{Algorithm:SHA-512}]]]",
                            "PasswordBasedKeyDerivationFunction:PBKDF2-SHA-512[KeyDerivation:KEYDERIVATION, "
                                    + "MessageDigest:SHA-512[BlockSize:1024, Digest:DIGEST, DigestSize:512, "
                                    + "Oid:2.16.840.1.101.3.4.2.3]]"),
                    // 27: EVP_KDF *hkdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
                    finding(
                            "KeyDerivationFunctionContext{Algorithm:HKDF}[KeyDerivationFunctionContext{}[KeyDerivationFunctionContext{}[DigestContext{Algorithm:SHA-256}]]]",
                            "KeyDerivationFunction:HKDF-SHA-256[KeyDerivation:KEYDERIVATION, "
                                    + "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, DigestSize:256, "
                                    + "Oid:2.16.840.1.101.3.4.2.1]]"),
                    // 35: EVP_KDF *sshkdf = EVP_KDF_fetch(NULL, "SSHKDF", NULL);
                    finding(
                            "KeyDerivationFunctionContext{Algorithm:SSHKDF}[KeyDerivationFunctionContext{}[KeyDerivationFunctionContext{}[DigestContext{Algorithm:SHA-512}]]]",
                            "KeyDerivationFunction:SSHKDF-SHA-512[KeyDerivation:KEYDERIVATION, "
                                    + "MessageDigest:SHA-512[BlockSize:1024, Digest:DIGEST, DigestSize:512, "
                                    + "Oid:2.16.840.1.101.3.4.2.3]]"),
                    // 45: EVP_KDF_CTX *hkdf_ctx = EVP_KDF_CTX_new(EVP_KDF_fetch(NULL, "HKDF",
                    // NULL));
                    finding(
                            "KeyDerivationFunctionContext{Algorithm:HKDF}[KeyDerivationFunctionContext{}[KeyDerivationFunctionContext{}[DigestContext{Algorithm:SHA-384}]]]",
                            "KeyDerivationFunction:HKDF-SHA-384[KeyDerivation:KEYDERIVATION, "
                                    + "MessageDigest:SHA-384[BlockSize:1024, Digest:DIGEST, DigestSize:384, "
                                    + "Oid:2.16.840.1.101.3.4.2.2]]"),
                    // 46: EVP_KDF_CTX *pbkdf2_ctx = EVP_KDF_CTX_new(EVP_KDF_fetch(NULL, "PBKDF2",
                    // NULL));
                    finding(
                            "KeyDerivationFunctionContext{Algorithm:PBKDF2}",
                            "PasswordBasedKeyDerivationFunction:PBKDF2[KeyDerivation:KEYDERIVATION]"),
                    // 55: EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
                    finding(
                            "KeyDerivationFunctionContext{Algorithm:HKDF}[KeyDerivationFunctionContext{}[KeyDerivationFunctionContext{KeySize:256}]]",
                            "KeyDerivationFunction:HKDF[KeyDerivation:KEYDERIVATION, KeyLength:256]"),
                    // 61: EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
                    finding(
                            "KeyDerivationFunctionContext{Algorithm:HKDF}[KeyDerivationFunctionContext{}[KeyDerivationFunctionContext{}[DigestContext{Algorithm:SHA-256}]]]",
                            "KeyDerivationFunction:HKDF-SHA-256[KeyDerivation:KEYDERIVATION, "
                                    + "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, DigestSize:256, "
                                    + "Oid:2.16.840.1.101.3.4.2.1]]"),
                    // 72: EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
                    finding(
                            "KeyDerivationFunctionContext{Algorithm:HKDF}[KeyDerivationFunctionContext{}[KeyDerivationFunctionContext{}[DigestContext{Algorithm:SHA-384}]]]",
                            "KeyDerivationFunction:HKDF-SHA-384[KeyDerivation:KEYDERIVATION, "
                                    + "MessageDigest:SHA-384[BlockSize:1024, Digest:DIGEST, DigestSize:384, "
                                    + "Oid:2.16.840.1.101.3.4.2.2]]"),
                    // 82: EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
                    finding(
                            "KeyDerivationFunctionContext{Algorithm:HKDF}[KeyDerivationFunctionContext{}[KeyDerivationFunctionContext{}[DigestContext{Algorithm:SHA-512}]]]",
                            "KeyDerivationFunction:HKDF-SHA-512[KeyDerivation:KEYDERIVATION, "
                                    + "MessageDigest:SHA-512[BlockSize:1024, Digest:DIGEST, DigestSize:512, "
                                    + "Oid:2.16.840.1.101.3.4.2.3]]"),
                    // 92: EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
                    finding(
                            "KeyDerivationFunctionContext{Algorithm:HKDF}[KeyDerivationFunctionContext{}[KeyDerivationFunctionContext{KeySize:256}[DigestContext{Algorithm:SHA-256}]]]",
                            "KeyDerivationFunction:HKDF-SHA-256[KeyDerivation:KEYDERIVATION, KeyLength:256, "
                                    + "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, DigestSize:256, "
                                    + "Oid:2.16.840.1.101.3.4.2.1]]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/kdf/OpenSSLEvpKdfContextTestFile.cc", this);
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
