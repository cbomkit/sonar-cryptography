/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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
 * PKCS#12 and PKCS#5 password-based encryption, key generation and MAC functions report the scheme
 * with the cipher and digest passed to them, and PKCS12_create reports the schemes selected by its
 * key and certificate NIDs.
 */
class OpenSSLPkcs12Test extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 5: PKCS12_PBE_keyivgen(ctx, "password", 8, param, EVP_des_ede3_cbc(),
                    // EVP_sha1(), 1);
                    finding(
                            "KeyDerivationFunctionContext{ValueAction:PKCS12-PBE}[CipherContext{ValueAction:DESede3-CBC}, "
                                    + "DigestContext{ValueAction:SHA-1}]",
                            "PasswordBasedEncryption:PKCS12-DESede168-CBC-SHA-1[BlockCipher:DESede168-CBC[BlockSize:64, "
                                    + "KeyLength:168, Mode:CBC], MessageDigest:SHA-1[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:160, Oid:1.3.14.3.2.26]]"),
                    // 9: PKCS5_PBE_keyivgen_ex(ctx, "password", 8, param, EVP_rc2_cbc(), EVP_md5(),
                    // 1, NULL, NULL);
                    finding(
                            "KeyDerivationFunctionContext{ValueAction:PBES1}[CipherContext{ValueAction:RC2-CBC}, "
                                    + "DigestContext{ValueAction:MD5}]",
                            "PasswordBasedEncryption:PBES1-RC2-128-CBC-MD5[BlockCipher:RC2-128-CBC[KeyLength:128, "
                                    + "Mode:CBC], MessageDigest:MD5[BlockSize:512, Digest:DIGEST, DigestSize:128], "
                                    + "Oid:1.2.840.113549.1.5.6]"),
                    // 13: PKCS12_key_gen_utf8_ex("password", 8, salt, 8, 1, 2048, 32, out,
                    // EVP_sha256(), NULL, NULL);
                    finding(
                            "KeyDerivationFunctionContext{ValueAction:PKCS12KDF}[DigestContext{ValueAction:SHA-256}]",
                            "PasswordBasedKeyDerivationFunction:PKCS12KDF-SHA-256[KeyDerivation:KEYDERIVATION, "
                                    + "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, DigestSize:256, "
                                    + "Oid:2.16.840.1.101.3.4.2.1]]"),
                    // 17: PKCS12_set_mac(p12, "password", 8, salt, 8, 2048, EVP_sha256());
                    finding(
                            "MacContext{ValueAction:HMAC}[DigestContext{ValueAction:SHA-256}]",
                            "Mac:HMAC-SHA-256[MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], Oid:1.2.840.113549.2.9, "
                                    + "Tag:TAG]"),
                    // 21: PKCS12_create("password", "key", pkey, cert, NULL,
                    // NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
                    finding(
                            "KeyDerivationFunctionContext{ValueAction:PBE-SHA1-3DES, "
                                    + "ValueAction:PBE-SHA1-RC2-40}",
                            "PasswordBasedEncryption:PKCS12-DESede168-CBC-SHA-1[BlockCipher:DESede168-CBC[BlockSize:64, "
                                    + "KeyLength:168, Mode:CBC], MessageDigest:SHA-1[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:160, Oid:1.3.14.3.2.26]]",
                            "PasswordBasedEncryption:PKCS12-RC2-40-CBC-SHA-1[BlockCipher:RC2-40-CBC[KeyLength:40, "
                                    + "Mode:CBC], MessageDigest:SHA-1[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:160, Oid:1.3.14.3.2.26]]"),
                    // 23: PKCS12_create_ex("password", "key", pkey, cert, NULL, NID_aes_256_cbc, 0,
                    // 2048, 2048, 0,
                    finding(
                            "KeyDerivationFunctionContext{ValueAction:PBES2-AES-256-CBC, "
                                    + "ValueAction:PBES2-AES-256-CBC}",
                            "PasswordBasedEncryption:PBES2-AES-256-CBC-HMAC-SHA-256[BlockCipher:AES-256-CBC[BlockSize:128, "
                                    + "KeyLength:256, Mode:CBC, Oid:2.16.840.1.101.3.4.1.42], "
                                    + "Mac:HMAC-SHA-256[MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], Oid:1.2.840.113549.2.9, "
                                    + "Tag:TAG], Oid:1.2.840.113549.1.5]",
                            "PasswordBasedEncryption:PBES2-AES-256-CBC-HMAC-SHA-256[BlockCipher:AES-256-CBC[BlockSize:128, "
                                    + "KeyLength:256, Mode:CBC, Oid:2.16.840.1.101.3.4.1.42], "
                                    + "Mac:HMAC-SHA-256[MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], Oid:1.2.840.113549.2.9, "
                                    + "Tag:TAG], Oid:1.2.840.113549.1.5]"),
                    // 30: PKCS12_PBE_keyivgen_ex(ctx, "password", 8, param, EVP_aes_128_cbc(),
                    // EVP_sha256(), 0, NULL,
                    finding(
                            "KeyDerivationFunctionContext{ValueAction:PKCS12-PBE}[CipherContext{ValueAction:AES-128-CBC}, "
                                    + "DigestContext{ValueAction:SHA-256}]",
                            "PasswordBasedEncryption:PKCS12-AES-128-CBC-SHA-256[BlockCipher:AES-128-CBC[BlockSize:128, "
                                    + "KeyLength:128, Mode:CBC, Oid:2.16.840.1.101.3.4.1.2], "
                                    + "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, DigestSize:256, "
                                    + "Oid:2.16.840.1.101.3.4.2.1]]"),
                    // 32: PKCS5_PBE_keyivgen(ctx, "password", 8, param, EVP_des_cbc(), EVP_md5(),
                    // 0);
                    finding(
                            "KeyDerivationFunctionContext{ValueAction:PBES1}[CipherContext{ValueAction:DES-CBC}, "
                                    + "DigestContext{ValueAction:MD5}]",
                            "PasswordBasedEncryption:PBES1-DES-56-CBC-MD5[BlockCipher:DES-56-CBC[BlockSize:64, "
                                    + "KeyLength:56, Mode:CBC], MessageDigest:MD5[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:128], Oid:1.2.840.113549.1.5.3]"),
                    // 33: PKCS12_key_gen_asc("password", 8, salt, 8, 1, 2048, 24, out, EVP_sha1());
                    finding(
                            "KeyDerivationFunctionContext{ValueAction:PKCS12KDF}[DigestContext{ValueAction:SHA-1}]",
                            "PasswordBasedKeyDerivationFunction:PKCS12KDF-SHA-1[KeyDerivation:KEYDERIVATION, "
                                    + "MessageDigest:SHA-1[BlockSize:512, Digest:DIGEST, DigestSize:160, "
                                    + "Oid:1.3.14.3.2.26]]"),
                    // 34: PKCS12_key_gen_asc_ex("password", 8, salt, 8, 2, 2048, 8, out,
                    // EVP_sha1(), NULL, NULL);
                    finding(
                            "KeyDerivationFunctionContext{ValueAction:PKCS12KDF}[DigestContext{ValueAction:SHA-1}]",
                            "PasswordBasedKeyDerivationFunction:PKCS12KDF-SHA-1[KeyDerivation:KEYDERIVATION, "
                                    + "MessageDigest:SHA-1[BlockSize:512, Digest:DIGEST, DigestSize:160, "
                                    + "Oid:1.3.14.3.2.26]]"),
                    // 35: PKCS12_key_gen_uni(uni_pass, 18, salt, 8, 3, 2048, 20, out, EVP_sha1());
                    finding(
                            "KeyDerivationFunctionContext{ValueAction:PKCS12KDF}[DigestContext{ValueAction:SHA-1}]",
                            "PasswordBasedKeyDerivationFunction:PKCS12KDF-SHA-1[KeyDerivation:KEYDERIVATION, "
                                    + "MessageDigest:SHA-1[BlockSize:512, Digest:DIGEST, DigestSize:160, "
                                    + "Oid:1.3.14.3.2.26]]"),
                    // 36: PKCS12_key_gen_uni_ex(uni_pass, 18, salt, 8, 3, 2048, 20, out,
                    // EVP_sha1(), NULL, NULL);
                    finding(
                            "KeyDerivationFunctionContext{ValueAction:PKCS12KDF}[DigestContext{ValueAction:SHA-1}]",
                            "PasswordBasedKeyDerivationFunction:PKCS12KDF-SHA-1[KeyDerivation:KEYDERIVATION, "
                                    + "MessageDigest:SHA-1[BlockSize:512, Digest:DIGEST, DigestSize:160, "
                                    + "Oid:1.3.14.3.2.26]]"),
                    // 37: PKCS12_key_gen_utf8("password", 8, salt, 8, 1, 2048, 32, out,
                    // EVP_sha512());
                    finding(
                            "KeyDerivationFunctionContext{ValueAction:PKCS12KDF}[DigestContext{ValueAction:SHA-512}]",
                            "PasswordBasedKeyDerivationFunction:PKCS12KDF-SHA-512[KeyDerivation:KEYDERIVATION, "
                                    + "MessageDigest:SHA-512[BlockSize:1024, Digest:DIGEST, DigestSize:512, "
                                    + "Oid:2.16.840.1.101.3.4.2.3]]"),
                    // 38: PKCS12_create_ex2("password", "key", pkey, cert, NULL,
                    // NID_pbe_WithSHA1And128BitRC4,
                    finding(
                            "KeyDerivationFunctionContext{ValueAction:PBE-SHA1-RC4-128, "
                                    + "ValueAction:PBES2-AES-128-CBC}",
                            "PasswordBasedEncryption:PKCS12-RC4-128-SHA-1[MessageDigest:SHA-1[BlockSize:512, "
                                    + "Digest:DIGEST, DigestSize:160, Oid:1.3.14.3.2.26], "
                                    + "StreamCipher:RC4-128[KeyLength:128]]",
                            "PasswordBasedEncryption:PBES2-AES-128-CBC-HMAC-SHA-256[BlockCipher:AES-128-CBC[BlockSize:128, "
                                    + "KeyLength:128, Mode:CBC, Oid:2.16.840.1.101.3.4.1.2], "
                                    + "Mac:HMAC-SHA-256[MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], Oid:1.2.840.113549.2.9, "
                                    + "Tag:TAG], Oid:1.2.840.113549.1.5]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/kdf/OpenSSLPkcs12TestFile.cc", this);
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
