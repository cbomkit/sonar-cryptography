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
package com.ibm.plugin.rules.detection.openssl.cipher;

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
 * Covers the algorithm values detected via {@code EVP_CIPHER_fetch}, both as string literals and
 * via a local variable holding one of those same values.
 */
class OpenSSLEvpCipherFetchTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 9: EVP_CIPHER_fetch(lib, "AES-128-SIV", props);
                    finding(
                            "CipherContext{Algorithm:AES-128-SIV}",
                            "BlockCipher:AES-128-SIV[BlockSize:128, KeyLength:128, Mode:SIV, "
                                    + "Oid:2.16.840.1.101.3.4.1]"),
                    // 10: EVP_CIPHER_fetch(lib, "AES-192-SIV", props);
                    finding(
                            "CipherContext{Algorithm:AES-192-SIV}",
                            "BlockCipher:AES-192-SIV[BlockSize:128, KeyLength:192, Mode:SIV, "
                                    + "Oid:2.16.840.1.101.3.4.1.2]"),
                    // 11: EVP_CIPHER_fetch(lib, "AES-256-SIV", props);
                    finding(
                            "CipherContext{Algorithm:AES-256-SIV}",
                            "BlockCipher:AES-256-SIV[BlockSize:128, KeyLength:256, Mode:SIV, "
                                    + "Oid:2.16.840.1.101.3.4.1.4]"),
                    // 14: EVP_CIPHER_fetch(lib, "AES-128-GCM-SIV", props);
                    finding(
                            "CipherContext{Algorithm:AES-128-GCM-SIV}",
                            "BlockCipher:AES-128-GCM-SIV[BlockSize:128, KeyLength:128, Mode:GCM-SIV, "
                                    + "Oid:2.16.840.1.101.3.4.1]"),
                    // 15: EVP_CIPHER_fetch(lib, "AES-192-GCM-SIV", props);
                    finding(
                            "CipherContext{Algorithm:AES-192-GCM-SIV}",
                            "BlockCipher:AES-192-GCM-SIV[BlockSize:128, KeyLength:192, Mode:GCM-SIV, "
                                    + "Oid:2.16.840.1.101.3.4.1.2]"),
                    // 16: EVP_CIPHER_fetch(lib, "AES-256-GCM-SIV", props);
                    finding(
                            "CipherContext{Algorithm:AES-256-GCM-SIV}",
                            "BlockCipher:AES-256-GCM-SIV[BlockSize:128, KeyLength:256, Mode:GCM-SIV, "
                                    + "Oid:2.16.840.1.101.3.4.1.4]"),
                    // 19: EVP_CIPHER_fetch(lib, "AES-128-CBC-CTS", props);
                    finding(
                            "CipherContext{Algorithm:AES-128-CBC-CTS}",
                            "BlockCipher:AES-128-CBC-CTS[BlockSize:128, KeyLength:128, Mode:CBC-CTS, "
                                    + "Oid:2.16.840.1.101.3.4.1]"),
                    // 20: EVP_CIPHER_fetch(lib, "AES-192-CBC-CTS", props);
                    finding(
                            "CipherContext{Algorithm:AES-192-CBC-CTS}",
                            "BlockCipher:AES-192-CBC-CTS[BlockSize:128, KeyLength:192, Mode:CBC-CTS, "
                                    + "Oid:2.16.840.1.101.3.4.1.2]"),
                    // 21: EVP_CIPHER_fetch(lib, "AES-256-CBC-CTS", props);
                    finding(
                            "CipherContext{Algorithm:AES-256-CBC-CTS}",
                            "BlockCipher:AES-256-CBC-CTS[BlockSize:128, KeyLength:256, Mode:CBC-CTS, "
                                    + "Oid:2.16.840.1.101.3.4.1.4]"),
                    // 24: EVP_CIPHER_fetch(lib, "AES-128-WRAP-INV", props);
                    finding(
                            "CipherContext{Algorithm:AES-128-WRAP-INV}",
                            "BlockCipher:AES-128-WRAP-INV[BlockSize:128, KeyLength:128, Mode:WRAP-INV, "
                                    + "Oid:2.16.840.1.101.3.4.1]"),
                    // 25: EVP_CIPHER_fetch(lib, "AES-192-WRAP-INV", props);
                    finding(
                            "CipherContext{Algorithm:AES-192-WRAP-INV}",
                            "BlockCipher:AES-192-WRAP-INV[BlockSize:128, KeyLength:192, Mode:WRAP-INV, "
                                    + "Oid:2.16.840.1.101.3.4.1.2]"),
                    // 26: EVP_CIPHER_fetch(lib, "AES-256-WRAP-INV", props);
                    finding(
                            "CipherContext{Algorithm:AES-256-WRAP-INV}",
                            "BlockCipher:AES-256-WRAP-INV[BlockSize:128, KeyLength:256, Mode:WRAP-INV, "
                                    + "Oid:2.16.840.1.101.3.4.1.4]"),
                    // 29: EVP_CIPHER_fetch(lib, "AES-128-WRAP-PAD-INV", props);
                    finding(
                            "CipherContext{Algorithm:AES-128-WRAP-PAD-INV}",
                            "BlockCipher:AES-128-WRAP-PAD-INV[BlockSize:128, KeyLength:128, "
                                    + "Mode:WRAP-PAD-INV, Oid:2.16.840.1.101.3.4.1]"),
                    // 30: EVP_CIPHER_fetch(lib, "AES-192-WRAP-PAD-INV", props);
                    finding(
                            "CipherContext{Algorithm:AES-192-WRAP-PAD-INV}",
                            "BlockCipher:AES-192-WRAP-PAD-INV[BlockSize:128, KeyLength:192, "
                                    + "Mode:WRAP-PAD-INV, Oid:2.16.840.1.101.3.4.1.2]"),
                    // 31: EVP_CIPHER_fetch(lib, "AES-256-WRAP-PAD-INV", props);
                    finding(
                            "CipherContext{Algorithm:AES-256-WRAP-PAD-INV}",
                            "BlockCipher:AES-256-WRAP-PAD-INV[BlockSize:128, KeyLength:256, "
                                    + "Mode:WRAP-PAD-INV, Oid:2.16.840.1.101.3.4.1.4]"),
                    // 34: EVP_CIPHER_fetch(lib, "AES-128-CBC-HMAC-SHA1", props);
                    finding(
                            "CipherContext{Algorithm:AES-128-CBC-HMAC-SHA1}",
                            "BlockCipher:AES-128-CBC-HMAC-SHA1[BlockSize:128, KeyLength:128, "
                                    + "Mode:CBC-HMAC-SHA1, Oid:2.16.840.1.101.3.4.1]"),
                    // 35: EVP_CIPHER_fetch(lib, "AES-128-CBC-HMAC-SHA256", props);
                    finding(
                            "CipherContext{Algorithm:AES-128-CBC-HMAC-SHA256}",
                            "BlockCipher:AES-128-CBC-HMAC-SHA256[BlockSize:128, KeyLength:128, "
                                    + "Mode:CBC-HMAC-SHA256, Oid:2.16.840.1.101.3.4.1]"),
                    // 36: EVP_CIPHER_fetch(lib, "AES-192-CBC-HMAC-SHA1", props);
                    finding(
                            "CipherContext{Algorithm:AES-192-CBC-HMAC-SHA1}",
                            "BlockCipher:AES-192-CBC-HMAC-SHA1[BlockSize:128, KeyLength:192, "
                                    + "Mode:CBC-HMAC-SHA1, Oid:2.16.840.1.101.3.4.1.2]"),
                    // 37: EVP_CIPHER_fetch(lib, "AES-192-CBC-HMAC-SHA256", props);
                    finding(
                            "CipherContext{Algorithm:AES-192-CBC-HMAC-SHA256}",
                            "BlockCipher:AES-192-CBC-HMAC-SHA256[BlockSize:128, KeyLength:192, "
                                    + "Mode:CBC-HMAC-SHA256, Oid:2.16.840.1.101.3.4.1.2]"),
                    // 38: EVP_CIPHER_fetch(lib, "AES-256-CBC-HMAC-SHA1", props);
                    finding(
                            "CipherContext{Algorithm:AES-256-CBC-HMAC-SHA1}",
                            "BlockCipher:AES-256-CBC-HMAC-SHA1[BlockSize:128, KeyLength:256, "
                                    + "Mode:CBC-HMAC-SHA1, Oid:2.16.840.1.101.3.4.1.4]"),
                    // 39: EVP_CIPHER_fetch(lib, "AES-256-CBC-HMAC-SHA256", props);
                    finding(
                            "CipherContext{Algorithm:AES-256-CBC-HMAC-SHA256}",
                            "BlockCipher:AES-256-CBC-HMAC-SHA256[BlockSize:128, KeyLength:256, "
                                    + "Mode:CBC-HMAC-SHA256, Oid:2.16.840.1.101.3.4.1.4]"),
                    // 42: EVP_CIPHER_fetch(lib, "AES-128-CBC-HMAC-SHA1-ETM", props);
                    finding(
                            "CipherContext{Algorithm:AES-128-CBC-HMAC-SHA1-ETM}",
                            "BlockCipher:AES-128-CBC-HMAC-SHA1-ETM[BlockSize:128, KeyLength:128, "
                                    + "Mode:CBC-HMAC-SHA1-ETM, Oid:2.16.840.1.101.3.4.1]"),
                    // 43: EVP_CIPHER_fetch(lib, "AES-192-CBC-HMAC-SHA1-ETM", props);
                    finding(
                            "CipherContext{Algorithm:AES-192-CBC-HMAC-SHA1-ETM}",
                            "BlockCipher:AES-192-CBC-HMAC-SHA1-ETM[BlockSize:128, KeyLength:192, "
                                    + "Mode:CBC-HMAC-SHA1-ETM, Oid:2.16.840.1.101.3.4.1.2]"),
                    // 44: EVP_CIPHER_fetch(lib, "AES-256-CBC-HMAC-SHA1-ETM", props);
                    finding(
                            "CipherContext{Algorithm:AES-256-CBC-HMAC-SHA1-ETM}",
                            "BlockCipher:AES-256-CBC-HMAC-SHA1-ETM[BlockSize:128, KeyLength:256, "
                                    + "Mode:CBC-HMAC-SHA1-ETM, Oid:2.16.840.1.101.3.4.1.4]"),
                    // 45: EVP_CIPHER_fetch(lib, "AES-128-CBC-HMAC-SHA256-ETM", props);
                    finding(
                            "CipherContext{Algorithm:AES-128-CBC-HMAC-SHA256-ETM}",
                            "BlockCipher:AES-128-CBC-HMAC-SHA256-ETM[BlockSize:128, KeyLength:128, "
                                    + "Mode:CBC-HMAC-SHA256-ETM, Oid:2.16.840.1.101.3.4.1]"),
                    // 46: EVP_CIPHER_fetch(lib, "AES-192-CBC-HMAC-SHA256-ETM", props);
                    finding(
                            "CipherContext{Algorithm:AES-192-CBC-HMAC-SHA256-ETM}",
                            "BlockCipher:AES-192-CBC-HMAC-SHA256-ETM[BlockSize:128, KeyLength:192, "
                                    + "Mode:CBC-HMAC-SHA256-ETM, Oid:2.16.840.1.101.3.4.1.2]"),
                    // 47: EVP_CIPHER_fetch(lib, "AES-256-CBC-HMAC-SHA256-ETM", props);
                    finding(
                            "CipherContext{Algorithm:AES-256-CBC-HMAC-SHA256-ETM}",
                            "BlockCipher:AES-256-CBC-HMAC-SHA256-ETM[BlockSize:128, KeyLength:256, "
                                    + "Mode:CBC-HMAC-SHA256-ETM, Oid:2.16.840.1.101.3.4.1.4]"),
                    // 48: EVP_CIPHER_fetch(lib, "AES-128-CBC-HMAC-SHA512-ETM", props);
                    finding(
                            "CipherContext{Algorithm:AES-128-CBC-HMAC-SHA512-ETM}",
                            "BlockCipher:AES-128-CBC-HMAC-SHA512-ETM[BlockSize:128, KeyLength:128, "
                                    + "Mode:CBC-HMAC-SHA512-ETM, Oid:2.16.840.1.101.3.4.1]"),
                    // 49: EVP_CIPHER_fetch(lib, "AES-192-CBC-HMAC-SHA512-ETM", props);
                    finding(
                            "CipherContext{Algorithm:AES-192-CBC-HMAC-SHA512-ETM}",
                            "BlockCipher:AES-192-CBC-HMAC-SHA512-ETM[BlockSize:128, KeyLength:192, "
                                    + "Mode:CBC-HMAC-SHA512-ETM, Oid:2.16.840.1.101.3.4.1.2]"),
                    // 50: EVP_CIPHER_fetch(lib, "AES-256-CBC-HMAC-SHA512-ETM", props);
                    finding(
                            "CipherContext{Algorithm:AES-256-CBC-HMAC-SHA512-ETM}",
                            "BlockCipher:AES-256-CBC-HMAC-SHA512-ETM[BlockSize:128, KeyLength:256, "
                                    + "Mode:CBC-HMAC-SHA512-ETM, Oid:2.16.840.1.101.3.4.1.4]"),
                    // 53: EVP_CIPHER_fetch(lib, "CAMELLIA-128-CBC-CTS", props);
                    finding(
                            "CipherContext{Algorithm:CAMELLIA-128-CBC-CTS}",
                            "BlockCipher:CAMELLIA-128-CBC-CTS[KeyLength:128, Mode:CBC-CTS]"),
                    // 54: EVP_CIPHER_fetch(lib, "CAMELLIA-192-CBC-CTS", props);
                    finding(
                            "CipherContext{Algorithm:CAMELLIA-192-CBC-CTS}",
                            "BlockCipher:CAMELLIA-192-CBC-CTS[KeyLength:192, Mode:CBC-CTS]"),
                    // 55: EVP_CIPHER_fetch(lib, "CAMELLIA-256-CBC-CTS", props);
                    finding(
                            "CipherContext{Algorithm:CAMELLIA-256-CBC-CTS}",
                            "BlockCipher:CAMELLIA-256-CBC-CTS[KeyLength:256, Mode:CBC-CTS]"),
                    // 59: EVP_CIPHER_fetch(lib, alg, props);
                    finding(
                            "CipherContext{Algorithm:AES-128-SIV}",
                            "BlockCipher:AES-128-SIV[BlockSize:128, KeyLength:128, Mode:SIV, "
                                    + "Oid:2.16.840.1.101.3.4.1]"),
                    // 63: EVP_CIPHER_fetch(lib, alg2, props);
                    finding(
                            "CipherContext{Algorithm:AES-192-SIV, Algorithm:AES-256-SIV}",
                            "BlockCipher:AES-192-SIV[BlockSize:128, KeyLength:192, Mode:SIV, "
                                    + "Oid:2.16.840.1.101.3.4.1.2]",
                            "BlockCipher:AES-256-SIV[BlockSize:128, KeyLength:256, Mode:SIV, "
                                    + "Oid:2.16.840.1.101.3.4.1.4]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/cipher/OpenSSLEvpCipherFetchTestFile.cc", this);
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
