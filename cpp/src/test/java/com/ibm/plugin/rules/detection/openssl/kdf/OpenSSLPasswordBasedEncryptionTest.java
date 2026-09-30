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
 * Password-based encryption selected by its algorithm identifier ({@link
 * OpenSSLPasswordBasedEncryption}): {@code PKCS8_encrypt} with PBES2 and a cipher (-1), a PKCS#12
 * or a PKCS#5 v1.5 scheme, with its salt length and iteration count, and {@code EVP_PBE_CipherInit}
 * with the scheme of an {@code OBJ_nid2obj} object, for its operation.
 */
class OpenSSLPasswordBasedEncryptionTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 8: PKCS8_encrypt(-1, EVP_aes_256_cbc(), pass, 8, salt, 16, 600000, p8inf);
                    finding(
                            "KeyDerivationFunctionContext{ValueAction:PBES2}[KeyDerivationFunctionContext{SaltSize:128}, "
                                    + "KeyDerivationFunctionContext{IterationCount:600000}, "
                                    + "CipherContext{ValueAction:AES-256-CBC}]",
                            "PasswordBasedEncryption:PBES2-AES-256-CBC[BlockCipher:AES-256-CBC[BlockSize:128, "
                                    + "KeyLength:256, Mode:CBC, Oid:2.16.840.1.101.3.4.1.42], "
                                    + "NumberOfIterations:600000, Oid:1.2.840.113549.1.5, SaltLength:128]"),
                    // 12: PKCS8_encrypt(NID_pbe_WithSHA1And3_Key_TripleDES_CBC, NULL, pass, 8,
                    // NULL, 8, 2048, p8inf);
                    finding(
                            "KeyDerivationFunctionContext{ValueAction:PBE-SHA1-3DES}[KeyDerivationFunctionContext{SaltSize:64}, "
                                    + "KeyDerivationFunctionContext{IterationCount:2048}]",
                            "PasswordBasedEncryption:PKCS12-DESede168-CBC-SHA-1[BlockCipher:DESede168-CBC[BlockSize:64, "
                                    + "KeyLength:168, Mode:CBC], MessageDigest:SHA-1[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:160, Oid:1.3.14.3.2.26], NumberOfIterations:2048, SaltLength:64]"),
                    // 16: PKCS8_encrypt_ex(NID_pbeWithMD5AndDES_CBC, NULL, pass, 8, NULL, 8, 1000,
                    // p8inf, NULL, NULL);
                    finding(
                            "KeyDerivationFunctionContext{ValueAction:PBE-MD5-DES}[KeyDerivationFunctionContext{SaltSize:64}, "
                                    + "KeyDerivationFunctionContext{IterationCount:1000}]",
                            "PasswordBasedEncryption:PBES1-DES-56-CBC-MD5[BlockCipher:DES-56-CBC[BlockSize:64, "
                                    + "KeyLength:56, Mode:CBC], MessageDigest:MD5[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:128], NumberOfIterations:1000, Oid:1.2.840.113549.1.5.3, "
                                    + "SaltLength:64]"),
                    // 20: EVP_PBE_CipherInit(OBJ_nid2obj(NID_pbeWithSHA1AndDES_CBC), pass, 8,
                    // param, ctx, 0);
                    finding(
                            "CipherContext{CipherAction:DECRYPT}[KeyDerivationFunctionContext{ValueAction:PBE-SHA1-DES}]",
                            "PasswordBasedEncryption:PBES1-DES-56-CBC-SHA-1[BlockCipher:DES-56-CBC[BlockSize:64, "
                                    + "KeyLength:56, Mode:CBC], Decrypt:DECRYPT, "
                                    + "MessageDigest:SHA-1[BlockSize:512, Digest:DIGEST, DigestSize:160, "
                                    + "Oid:1.3.14.3.2.26], Oid:1.2.840.113549.1.5.10]"),
                    // 25: EVP_PBE_CipherInit_ex(scheme, pass, 8, param, ctx, 1, NULL, NULL);
                    finding(
                            "CipherContext{CipherAction:ENCRYPT}[KeyDerivationFunctionContext{ValueAction:PBE-SHA1-RC4-128}]",
                            "PasswordBasedEncryption:PKCS12-RC4-128-SHA-1[Encrypt:ENCRYPT, "
                                    + "MessageDigest:SHA-1[BlockSize:512, Digest:DIGEST, DigestSize:160, "
                                    + "Oid:1.3.14.3.2.26], StreamCipher:RC4-128[KeyLength:128]]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify(
                "rules/detection/openssl/kdf/OpenSSLPasswordBasedEncryptionTestFile.cc", this);
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
