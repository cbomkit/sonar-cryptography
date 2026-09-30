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
 * A key created from raw bytes is reported as a secret key holding its MAC algorithm, or as a
 * private key holding its asymmetric algorithm, with its size, as the Java module reports a {@code
 * SecretKeySpec}. The MAC computed with a MAC key through {@code EVP_DigestSign} is reported with
 * the digest or cipher it uses.
 */
class OpenSSLRawKeyTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 4: EVP_PKEY *pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, 32);
                    finding(
                            "KeyContext{ValueAction:HMAC}[SignatureContext{SignatureAction:SIGN}[DigestContext{ValueAction:SHA-256}], "
                                    + "KeyContext{KeySize:256}]",
                            "SecretKey:HMAC[KeyLength:256, "
                                    + "Mac:HMAC-SHA-256[MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], Oid:1.2.840.113549.2.9, "
                                    + "Tag:TAG]]"),
                    // 11: EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key,
                    // 64);
                    finding(
                            "KeyContext{ValueAction:HMAC}[SignatureContext{SignatureAction:SIGN}[DigestContext{ValueAction:SHA-512}], "
                                    + "KeyContext{KeySize:512}]",
                            "SecretKey:HMAC[KeyLength:512, "
                                    + "Mac:HMAC-SHA-512[MessageDigest:SHA-512[BlockSize:1024, Digest:DIGEST, "
                                    + "DigestSize:512, Oid:2.16.840.1.101.3.4.2.3], Oid:1.2.840.113549.2.11, "
                                    + "Tag:TAG]]"),
                    // 16: EVP_PKEY *pkey = EVP_PKEY_new_CMAC_key(NULL, key, 16, EVP_aes_128_cbc());
                    finding(
                            "KeyContext{ValueAction:CMAC}[SignatureContext{SignatureAction:SIGN}, "
                                    + "KeyContext{KeySize:128}, CipherContext{ValueAction:AES-128-CBC}]",
                            "SecretKey:CMAC[KeyLength:128, "
                                    + "Mac:CMAC-AES[BlockCipher:AES-128-CBC[BlockSize:128, KeyLength:128, "
                                    + "Mode:CBC, Oid:2.16.840.1.101.3.4.1.2], Tag:TAG]]"),
                    // 21: EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key_ex(NULL, "SIPHASH", NULL,
                    // key, 16);
                    finding(
                            "KeyContext{Algorithm:SIPHASH}[KeyContext{KeySize:128}]",
                            "SecretKey:SipHash[KeyLength:128, Mac:SipHash[DigestSize:64, KeyLength:128, "
                                    + "Tag:TAG]]"),
                    // 25: EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                    // priv, 32);
                    finding(
                            "KeyContext{ValueAction:ED25519}[SignatureContext{SignatureAction:SIGN}, "
                                    + "KeyContext{KeySize:256}]",
                            "PrivateKey:Ed25519[KeyLength:256, "
                                    + "Signature:Ed25519[EllipticCurve:Edwards25519, "
                                    + "MessageDigest:SHA-512[BlockSize:1024, Digest:DIGEST, DigestSize:512, "
                                    + "Oid:2.16.840.1.101.3.4.2.3], Oid:1.3.101.112, Sign:SIGN]]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/keygen/OpenSSLRawKeyTestFile.cc", this);
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
