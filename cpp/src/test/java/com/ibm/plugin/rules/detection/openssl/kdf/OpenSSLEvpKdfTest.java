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
 * Covers the KDF names accepted by {@code EVP_KDF_fetch} and the PBKDF2 functions of {@link
 * OpenSSLEvpKdfPkcs12}. Each fetched name is reported as its KDF; the digest set on a fetched KDF's
 * context is covered by {@link OpenSSLEvpKdfContextTest}, the EVP_PKEY interface by {@link
 * OpenSSLEvpPkeyKdfTest}, and the PKCS#12 and PKCS#5 password-based functions by {@link
 * OpenSSLPkcs12Test}.
 */
class OpenSSLEvpKdfTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 11: EVP_KDF_fetch(lib, "PBKDF2", props);
                    finding(
                            "KeyDerivationFunctionContext{Algorithm:PBKDF2}",
                            "PasswordBasedKeyDerivationFunction:PBKDF2[KeyDerivation:KEYDERIVATION]"),
                    // 12: EVP_KDF_fetch(lib, "HKDF", props);
                    finding(
                            "KeyDerivationFunctionContext{Algorithm:HKDF}",
                            "KeyDerivationFunction:HKDF[KeyDerivation:KEYDERIVATION]"),
                    // 13: EVP_KDF_fetch(lib, "SCRYPT", props);
                    finding(
                            "KeyDerivationFunctionContext{Algorithm:SCRYPT}",
                            "PasswordBasedKeyDerivationFunction:scrypt[KeyDerivation:KEYDERIVATION]"),
                    // 14: EVP_KDF_fetch(lib, "TLS1-PRF", props);
                    finding(
                            "KeyDerivationFunctionContext{Algorithm:TLS1-PRF}",
                            "KeyDerivationFunction:TLS-PRF[KeyDerivation:KEYDERIVATION]"),
                    // 15: EVP_KDF_fetch(lib, "TLS13-KDF", props);
                    finding(
                            "KeyDerivationFunctionContext{Algorithm:TLS13-KDF}",
                            "KeyDerivationFunction:HKDF[KeyDerivation:KEYDERIVATION]"),
                    // 16: EVP_KDF_fetch(lib, "X963KDF", props);
                    finding(
                            "KeyDerivationFunctionContext{Algorithm:X963KDF}",
                            "KeyDerivationFunction:ANSI-KDF-X9.63[KeyDerivation:KEYDERIVATION]"),
                    // 17: EVP_KDF_fetch(lib, "KBKDF", props);
                    finding(
                            "KeyDerivationFunctionContext{Algorithm:KBKDF}",
                            "KeyDerivationFunction:SP800_108_CounterKDF[KeyDerivation:KEYDERIVATION]"),
                    // 18: EVP_KDF_fetch(lib, "X942KDF-ASN1", props);
                    finding(
                            "KeyDerivationFunctionContext{Algorithm:X942KDF-ASN1}",
                            "KeyDerivationFunction:ANSI-KDF-X9.42-ASN1[KeyDerivation:KEYDERIVATION, "
                                    + "ParameterSetIdentifier:ASN1]"),
                    // 19: EVP_KDF_fetch(lib, "X942KDF-CONCAT", props);
                    finding(
                            "KeyDerivationFunctionContext{Algorithm:X942KDF-CONCAT}",
                            "KeyDerivationFunction:ANSI-KDF-X9.42-CONCAT[KeyDerivation:KEYDERIVATION, "
                                    + "ParameterSetIdentifier:CONCAT]"),
                    // 20: EVP_KDF_fetch(lib, "SSKDF", props);
                    finding(
                            "KeyDerivationFunctionContext{Algorithm:SSKDF}",
                            "KeyDerivationFunction:ConcatenationKDF[KeyDerivation:KEYDERIVATION]"),
                    // 21: EVP_KDF_fetch(lib, "SSHKDF", props);
                    finding(
                            "KeyDerivationFunctionContext{Algorithm:SSHKDF}",
                            "KeyDerivationFunction:SSHKDF[KeyDerivation:KEYDERIVATION]"),
                    // 22: EVP_KDF_fetch(lib, "KRB5KDF", props);
                    finding(
                            "KeyDerivationFunctionContext{Algorithm:KRB5KDF}",
                            "KeyDerivationFunction:KRB5KDF[KeyDerivation:KEYDERIVATION]"),
                    // 23: EVP_KDF_fetch(lib, "ARGON2D", props);
                    finding(
                            "KeyDerivationFunctionContext{Algorithm:ARGON2D}",
                            "PasswordBasedKeyDerivationFunction:Argon2d[KeyDerivation:KEYDERIVATION]"),
                    // 24: EVP_KDF_fetch(lib, "ARGON2I", props);
                    finding(
                            "KeyDerivationFunctionContext{Algorithm:ARGON2I}",
                            "PasswordBasedKeyDerivationFunction:Argon2i[KeyDerivation:KEYDERIVATION]"),
                    // 25: EVP_KDF_fetch(lib, "ARGON2ID", props);
                    finding(
                            "KeyDerivationFunctionContext{Algorithm:ARGON2ID}",
                            "PasswordBasedKeyDerivationFunction:Argon2id[KeyDerivation:KEYDERIVATION]"),
                    // 26: EVP_KDF_fetch(lib, "PKCS12KDF", props);
                    finding(
                            "KeyDerivationFunctionContext{Algorithm:PKCS12KDF}",
                            "PasswordBasedKeyDerivationFunction:PKCS12KDF[KeyDerivation:KEYDERIVATION]"),
                    // 27: EVP_KDF_fetch(lib, "PVKKDF", props);
                    finding(
                            "KeyDerivationFunctionContext{Algorithm:PVKKDF}",
                            "PasswordBasedKeyDerivationFunction:PVKKDF[KeyDerivation:KEYDERIVATION]"),
                    // 28: EVP_KDF_fetch(lib, "HMAC-DRBG-KDF", props);
                    finding(
                            "KeyDerivationFunctionContext{Algorithm:HMAC-DRBG-KDF}",
                            "KeyDerivationFunction:HMAC-DRBG-KDF[KeyDerivation:KEYDERIVATION]"),
                    // 33: PKCS5_PBKDF2_HMAC((char*)buf, 8, buf, 16, 1000, pbkdf2_md, 32, buf);
                    finding(
                            "KeyDerivationFunctionContext{ValueAction:PBKDF2-HMAC}[KeyDerivationFunctionContext{SaltSize:128}, "
                                    + "KeyDerivationFunctionContext{IterationCount:1000}, "
                                    + "KeyDerivationFunctionContext{KeySize:256}, "
                                    + "DigestContext{ValueAction:SHA-256}]",
                            "PasswordBasedKeyDerivationFunction:PBKDF2-SHA-256[KeyDerivation:KEYDERIVATION, "
                                    + "KeyLength:256, MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], NumberOfIterations:1000, "
                                    + "SaltLength:128]"),
                    // 34: PKCS5_PBKDF2_HMAC_SHA1((char*)buf, 8, buf, 16, 1000, 32, buf);
                    finding(
                            "KeyDerivationFunctionContext{ValueAction:PBKDF2-HMAC-SHA1}[KeyDerivationFunctionContext{SaltSize:128}, "
                                    + "KeyDerivationFunctionContext{IterationCount:1000}, "
                                    + "KeyDerivationFunctionContext{KeySize:256}]",
                            "PasswordBasedKeyDerivationFunction:PBKDF2-SHA-1[KeyDerivation:KEYDERIVATION, "
                                    + "KeyLength:256, MessageDigest:SHA-1[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:160, Oid:1.3.14.3.2.26], NumberOfIterations:1000, SaltLength:128]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/kdf/OpenSSLEvpKdfTestFile.cc", this);
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
