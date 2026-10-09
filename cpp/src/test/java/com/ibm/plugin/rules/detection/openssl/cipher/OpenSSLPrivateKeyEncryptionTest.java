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
 * A private key written encrypted is reported as the encryption with the cipher given to the writer
 * ({@link OpenSSLPrivateKeyEncryption}); a key written without a cipher is not encrypted and not
 * reported.
 */
class OpenSSLPrivateKeyEncryptionTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 5: PEM_write_bio_PrivateKey(out, pkey, EVP_aes_256_cbc(), NULL, 0, NULL,
                    // (void *) pass);
                    finding(
                            "CipherContext{CipherAction:ENCRYPT}[CipherContext{ValueAction:AES-256-CBC}]",
                            "BlockCipher:AES-256-CBC[BlockSize:128, Encrypt:ENCRYPT, KeyLength:256, "
                                    + "Mode:CBC, Oid:2.16.840.1.101.3.4.1.42]"),
                    // 10: PEM_write_bio_PKCS8PrivateKey(out, pkey, cipher, NULL, 0, NULL, (void *)
                    // pass);
                    finding(
                            "CipherContext{CipherAction:ENCRYPT}[CipherContext{ValueAction:AES-128-CBC}]",
                            "BlockCipher:AES-128-CBC[BlockSize:128, Encrypt:ENCRYPT, KeyLength:128, "
                                    + "Mode:CBC, Oid:2.16.840.1.101.3.4.1.2]"),
                    // 14: i2d_PKCS8PrivateKey_bio(out, pkey, EVP_des_ede3_cbc(), NULL, 0, NULL,
                    // (void *) pass);
                    finding(
                            "CipherContext{CipherAction:ENCRYPT}[CipherContext{ValueAction:DESede3-CBC}]",
                            "BlockCipher:DESede168-CBC[BlockSize:64, Encrypt:ENCRYPT, KeyLength:168, "
                                    + "Mode:CBC]"),
                    // 18: PEM_write_bio_PrivateKey_traditional(fp, pkey, EVP_aes_192_cbc(), NULL,
                    // 0, NULL, (void *) pass);
                    finding(
                            "CipherContext{CipherAction:ENCRYPT}[CipherContext{ValueAction:AES-192-CBC}]",
                            "BlockCipher:AES-192-CBC[BlockSize:128, Encrypt:ENCRYPT, KeyLength:192, "
                                    + "Mode:CBC, Oid:2.16.840.1.101.3.4.1.22]"),
                    // 26: PEM_write_PrivateKey(fp, pkey, EVP_aes_256_cbc(), NULL, 0, NULL, (void *)
                    // pass);
                    finding(
                            "CipherContext{CipherAction:ENCRYPT}[CipherContext{ValueAction:AES-256-CBC}]",
                            "BlockCipher:AES-256-CBC[BlockSize:128, Encrypt:ENCRYPT, KeyLength:256, "
                                    + "Mode:CBC, Oid:2.16.840.1.101.3.4.1.42]"),
                    // 27: PEM_write_PKCS8PrivateKey(fp, pkey, EVP_aes_128_cbc(), NULL, 0, NULL,
                    // (void *) pass);
                    finding(
                            "CipherContext{CipherAction:ENCRYPT}[CipherContext{ValueAction:AES-128-CBC}]",
                            "BlockCipher:AES-128-CBC[BlockSize:128, Encrypt:ENCRYPT, KeyLength:128, "
                                    + "Mode:CBC, Oid:2.16.840.1.101.3.4.1.2]"),
                    // 28: i2d_PKCS8PrivateKey_fp(fp, pkey, EVP_aes_192_cbc(), NULL, 0, NULL, (void
                    // *) pass);
                    finding(
                            "CipherContext{CipherAction:ENCRYPT}[CipherContext{ValueAction:AES-192-CBC}]",
                            "BlockCipher:AES-192-CBC[BlockSize:128, Encrypt:ENCRYPT, KeyLength:192, "
                                    + "Mode:CBC, Oid:2.16.840.1.101.3.4.1.22]"),
                    // 32: PEM_write_bio_PrivateKey_ex(out, pkey, EVP_aes_256_cbc(), NULL, 0, NULL,
                    // NULL, libctx, NULL);
                    finding(
                            "CipherContext{CipherAction:ENCRYPT}[CipherContext{ValueAction:AES-256-CBC}]",
                            "BlockCipher:AES-256-CBC[BlockSize:128, Encrypt:ENCRYPT, KeyLength:256, "
                                    + "Mode:CBC, Oid:2.16.840.1.101.3.4.1.42]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify(
                "rules/detection/openssl/cipher/OpenSSLPrivateKeyEncryptionTestFile.cc", this);
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
