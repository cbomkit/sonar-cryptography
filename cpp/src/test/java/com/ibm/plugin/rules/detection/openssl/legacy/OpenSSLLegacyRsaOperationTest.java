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
package com.ibm.plugin.rules.detection.openssl.legacy;

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
 * The legacy RSA operations report RSA with the scheme selected by their padding argument:
 * encryption and decryption with the public and private key, and the signature primitive with the
 * private key (RSA_private_encrypt) and its verification (RSA_public_decrypt).
 */
class OpenSSLLegacyRsaOperationTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 4: RSA_public_encrypt(len, in, out, rsa, RSA_PKCS1_OAEP_PADDING);
                    finding(
                            "CipherContext{CipherAction:ENCRYPT}[CipherContext{ValueAction:RSA-OAEP}]",
                            "PublicKeyEncryption:RSA-OAEP[Encrypt:ENCRYPT, Oid:1.2.840.113549.1.1.7, "
                                    + "Padding:OAEP]"),
                    // 5: RSA_private_decrypt(len, in, out, rsa, RSA_PKCS1_PADDING);
                    finding(
                            "CipherContext{CipherAction:DECRYPT}[CipherContext{ValueAction:RSA-PKCS1-TYPE2}]",
                            "PublicKeyEncryption:RSA[Decrypt:DECRYPT, Oid:1.2.840.113549.1.1.1, "
                                    + "Padding:PKCS1]"),
                    // 6: RSA_public_encrypt(len, in, out, rsa, RSA_NO_PADDING);
                    finding(
                            "CipherContext{CipherAction:ENCRYPT}[CipherContext{ValueAction:RSA-NO-PADDING}]",
                            "PublicKeyEncryption:RSA[Encrypt:ENCRYPT, Oid:1.2.840.113549.1.1.1]"),
                    // 10: RSA_private_encrypt(len, in, out, rsa, RSA_PKCS1_PADDING);
                    finding(
                            "SignatureContext{SignatureAction:SIGN}[SignatureContext{ValueAction:RSA-PKCS1}]",
                            "Signature:RSA-PKCS1-1.5[Oid:1.2.840.113549.1.1.1, Padding:PKCS1, Sign:SIGN]"),
                    // 11: RSA_public_decrypt(len, in, out, rsa, RSA_X931_PADDING);
                    finding(
                            "SignatureContext{SignatureAction:VERIFY}[SignatureContext{ValueAction:RSA-X931}]",
                            "Signature:ANSI X9.31[Verify:VERIFY]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify(
                "rules/detection/openssl/legacy/OpenSSLLegacyRsaOperationTestFile.cc", this);
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
