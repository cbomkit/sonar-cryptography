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
 * Covers all rule entries of the legacy cipher classes ({@link OpenSSLLegacyCipherAes}, {@link
 * OpenSSLLegacyCipherDes}, ...). The key setup functions report the key size given as their
 * argument. An encryption function reports the key size its key was set up with, and the key setup
 * is then reported with it; a key set up but not used is reported on its own, and a key given to
 * the function has no key size.
 *
 * <p>The fixture calls every function named by the rules, including the aliases of a rule matching
 * several functions ({@code forMethods(a, b, c)}).
 */
class OpenSSLLegacyCipherTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 20: AES_ecb_encrypt(buf, buf, &ak, 1);
                    finding(
                            "CipherContext{ValueAction:AES-ECB}[CipherContext{ValueAction:AES}[CipherContext{KeySize:256}]]",
                            "BlockCipher:AES-256-ECB[BlockSize:128, KeyLength:256, Mode:ECB, Oid:2.16.840.1.101.3.4.1.41]"),
                    // 21: AES_cbc_encrypt(buf, buf, 64, &ak, iv, 1);
                    finding(
                            "CipherContext{ValueAction:AES-CBC}[CipherContext{ValueAction:AES}[CipherContext{KeySize:256}]]",
                            "BlockCipher:AES-256-CBC[BlockSize:128, KeyLength:256, Mode:CBC, Oid:2.16.840.1.101.3.4.1.42]"),
                    // 22: AES_cfb128_encrypt(buf, buf, 64, &ak, iv, &num, 1);
                    finding(
                            "CipherContext{ValueAction:AES-CFB128}[CipherContext{ValueAction:AES}[CipherContext{KeySize:256}]]",
                            "BlockCipher:AES-256-CFB128[BlockSize:128, KeyLength:256, Mode:CFB128, Oid:2.16.840.1.101.3.4.1.44]"),
                    // 23: AES_ofb128_encrypt(buf, buf, 64, &ak, iv, &num);
                    finding(
                            "CipherContext{ValueAction:AES-OFB}[CipherContext{ValueAction:AES}[CipherContext{KeySize:256}]]",
                            "BlockCipher:AES-256-OFB[BlockSize:128, KeyLength:256, Mode:OFB, Oid:2.16.840.1.101.3.4.1.43]"),
                    // 24: AES_ige_encrypt(buf, buf, 64, &ak, iv, 1);
                    finding(
                            "CipherContext{ValueAction:AES-IGE}[CipherContext{ValueAction:AES}[CipherContext{KeySize:256}]]",
                            "BlockCipher:AES-256-IGE[BlockSize:128, KeyLength:256, Mode:IGE, Oid:2.16.840.1.101.3.4.1.4]"),
                    // 25: AES_cfb1_encrypt(buf, buf, 64, &ak, iv, &num, 1);
                    finding(
                            "CipherContext{ValueAction:AES-CFB1}[CipherContext{ValueAction:AES}[CipherContext{KeySize:256}]]",
                            "BlockCipher:AES-256-CFB1[BlockSize:128, KeyLength:256, Mode:CFB1, Oid:2.16.840.1.101.3.4.1.4]"),
                    // 26: AES_cfb8_encrypt(buf, buf, 64, &ak, iv, &num, 1);
                    finding(
                            "CipherContext{ValueAction:AES-CFB8}[CipherContext{ValueAction:AES}[CipherContext{KeySize:256}]]",
                            "BlockCipher:AES-256-CFB8[BlockSize:128, KeyLength:256, Mode:CFB8, Oid:2.16.840.1.101.3.4.1.4]"),
                    // 27: AES_bi_ige_encrypt(buf, buf, 64, &ak, &ak, iv, 1);
                    finding(
                            "CipherContext{ValueAction:AES-BI-IGE}[CipherContext{ValueAction:AES}[CipherContext{KeySize:256}]]",
                            "BlockCipher:AES-256-BI-IGE[BlockSize:128, KeyLength:256, Mode:BI-IGE, Oid:2.16.840.1.101.3.4.1.4]"),
                    // 29: AES_wrap_key(&ak, NULL, buf, buf, 32);
                    finding(
                            "CipherContext{ValueAction:AES-WRAP}[CipherContext{ValueAction:AES}[CipherContext{KeySize:256}]]",
                            "BlockCipher:AES-256-WRAP[BlockSize:128, KeyLength:256, Mode:WRAP, Oid:2.16.840.1.101.3.4.1.45]"),
                    // 30: AES_unwrap_key(&dk, NULL, buf, buf, 40);
                    finding(
                            "CipherContext{ValueAction:AES-WRAP}[CipherContext{ValueAction:AES}[CipherContext{KeySize:192}]]",
                            "BlockCipher:AES-192-WRAP[BlockSize:128, KeyLength:192, Mode:WRAP, Oid:2.16.840.1.101.3.4.1.25]"),
                    // 40: AES_ecb_encrypt(buf, buf, &k, 1);
                    finding(
                            "CipherContext{ValueAction:AES-ECB}[CipherContext{ValueAction:AES}[CipherContext{KeySize:128}, CipherContext{KeySize:256}]]",
                            "BlockCipher:AES-128-ECB[BlockSize:128, KeyLength:128, Mode:ECB, Oid:2.16.840.1.101.3.4.1.1]",
                            "BlockCipher:AES-256-ECB[BlockSize:128, KeyLength:256, Mode:ECB,"
                                    + " Oid:2.16.840.1.101.3.4.1.41]"),
                    // 46: AES_set_encrypt_key(buf, 128, &unused);
                    finding(
                            "CipherContext{ValueAction:AES}[CipherContext{KeySize:128}]",
                            "BlockCipher:AES-128[BlockSize:128, KeyLength:128, Oid:2.16.840.1.101.3.4.1]"),
                    // 50: AES_ecb_encrypt(buf, buf, key, 1);
                    finding(
                            "CipherContext{ValueAction:AES-ECB}",
                            "BlockCipher:AES-ECB[BlockSize:128, Mode:ECB, Oid:2.16.840.1.101.3.4.1]"),
                    // 60: DES_ecb_encrypt(&dc, &dc, &ds, 1);
                    finding(
                            "CipherContext{ValueAction:DES-ECB}[CipherContext{ValueAction:DES}]",
                            "BlockCipher:DES-56-ECB[BlockSize:64, KeyLength:56, Mode:ECB]"),
                    // 61: DES_ede3_cbc_encrypt(buf, buf, 64, &ds, &ds, &ds, &dc, 1);
                    finding(
                            "CipherContext{ValueAction:3DES-CBC}[CipherContext{ValueAction:DES}]",
                            "BlockCipher:DESede168-CBC[BlockSize:64, KeyLength:168, Mode:CBC]"),
                    // 62: DES_ecb3_encrypt(&dc, &dc, &ds, &ds, &ds, 1);
                    finding(
                            "CipherContext{ValueAction:3DES-ECB}[CipherContext{ValueAction:DES}]",
                            "BlockCipher:DESede168-ECB[BlockSize:64, KeyLength:168, Mode:ECB]"),
                    // 63: DES_ede3_cfb64_encrypt(buf, buf, 64, &ds, &ds, &ds, &dc, &num, 1);
                    finding(
                            "CipherContext{ValueAction:3DES-CFB}[CipherContext{ValueAction:DES}]",
                            "BlockCipher:DESede168-CFB[BlockSize:64, KeyLength:168, Mode:CFB]"),
                    // 64: DES_ofb64_encrypt(buf, buf, 64, &ds, &dc, &num);
                    finding(
                            "CipherContext{ValueAction:DES-OFB}[CipherContext{ValueAction:DES}]",
                            "BlockCipher:DES-56-OFB[BlockSize:64, KeyLength:56, Mode:OFB]"),
                    // 67: DES_ncbc_encrypt(buf, buf, 64, &ds, &dc, 1);
                    finding(
                            "CipherContext{ValueAction:DES-CBC}[CipherContext{ValueAction:DES}]",
                            "BlockCipher:DES-56-CBC[BlockSize:64, KeyLength:56, Mode:CBC]"),
                    // 68: DES_cbc_encrypt(buf, buf, 64, &ds, &dc, 1);
                    finding(
                            "CipherContext{ValueAction:DES-CBC}[CipherContext{ValueAction:DES}]",
                            "BlockCipher:DES-56-CBC[BlockSize:64, KeyLength:56, Mode:CBC]"),
                    // 69: DES_cfb64_encrypt(buf, buf, 64, &ds, &dc, &num, 1);
                    finding(
                            "CipherContext{ValueAction:DES-CFB}[CipherContext{ValueAction:DES}]",
                            "BlockCipher:DES-56-CFB[BlockSize:64, KeyLength:56, Mode:CFB]"),
                    // 70: DES_cfb_encrypt(buf, buf, 8, 64, &ds, &dc, 1);
                    finding(
                            "CipherContext{ValueAction:DES-CFB}[CipherContext{ValueAction:DES}]",
                            "BlockCipher:DES-56-CFB[BlockSize:64, KeyLength:56, Mode:CFB]"),
                    // 71: DES_ede3_cfb_encrypt(buf, buf, 8, 64, &ds, &ds, &ds, &dc, 1);
                    finding(
                            "CipherContext{ValueAction:3DES-CFB}[CipherContext{ValueAction:DES}]",
                            "BlockCipher:DESede168-CFB[BlockSize:64, KeyLength:168, Mode:CFB]"),
                    // 72: DES_ede3_ofb64_encrypt(buf, buf, 64, &ds, &ds, &ds, &dc, &num);
                    finding(
                            "CipherContext{ValueAction:3DES-OFB}[CipherContext{ValueAction:DES}]",
                            "BlockCipher:DESede168-OFB[BlockSize:64, KeyLength:168, Mode:OFB]"),
                    // 73: DES_xcbc_encrypt(buf, buf, 64, &ds, &dc, &dc, &dc, 1);
                    finding(
                            "CipherContext{ValueAction:DES-XCBC}[CipherContext{ValueAction:DES}]",
                            "BlockCipher:DESX-184-CBC[BlockSize:64, KeyLength:184, Mode:CBC]"),
                    // 82: BF_ecb_encrypt(buf, buf, &bk, 1);
                    finding(
                            "CipherContext{ValueAction:BLOWFISH-ECB}[CipherContext{ValueAction:BLOWFISH}[CipherContext{KeySize:160}]]",
                            "BlockCipher:Blowfish-160-ECB[KeyLength:160, Mode:ECB]"),
                    // 83: BF_cbc_encrypt(buf, buf, 64, &bk, iv, 1);
                    finding(
                            "CipherContext{ValueAction:BLOWFISH-CBC}[CipherContext{ValueAction:BLOWFISH}[CipherContext{KeySize:160}]]",
                            "BlockCipher:Blowfish-160-CBC[KeyLength:160, Mode:CBC]"),
                    // 84: BF_cfb64_encrypt(buf, buf, 64, &bk, iv, &num, 1);
                    finding(
                            "CipherContext{ValueAction:BLOWFISH-CFB}[CipherContext{ValueAction:BLOWFISH}[CipherContext{KeySize:160}]]",
                            "BlockCipher:Blowfish-160-CFB[KeyLength:160, Mode:CFB]"),
                    // 85: BF_ofb64_encrypt(buf, buf, 64, &bk, iv, &num);
                    finding(
                            "CipherContext{ValueAction:BLOWFISH-OFB}[CipherContext{ValueAction:BLOWFISH}[CipherContext{KeySize:160}]]",
                            "BlockCipher:Blowfish-160-OFB[KeyLength:160, Mode:OFB]"),
                    // 96: RC4(&r4, 64, buf, buf);
                    finding(
                            "CipherContext{ValueAction:RC4}[CipherContext{ValueAction:RC4}[CipherContext{KeySize:128}]]",
                            "StreamCipher:RC4-128[KeyLength:128]"),
                    // 98: RC2_ecb_encrypt(buf, buf, &r2, 1);
                    finding(
                            "CipherContext{ValueAction:RC2-ECB}[CipherContext{ValueAction:RC2}[CipherContext{KeySize:64}]]",
                            "BlockCipher:RC2-64-ECB[KeyLength:64, Mode:ECB]"),
                    // 99: RC2_cbc_encrypt(buf, buf, 64, &r2, iv, 1);
                    finding(
                            "CipherContext{ValueAction:RC2-CBC}[CipherContext{ValueAction:RC2}[CipherContext{KeySize:64}]]",
                            "BlockCipher:RC2-64-CBC[KeyLength:64, Mode:CBC]"),
                    // 100: RC2_cfb64_encrypt(buf, buf, 64, &r2, iv, &num, 1);
                    finding(
                            "CipherContext{ValueAction:RC2-CFB}[CipherContext{ValueAction:RC2}[CipherContext{KeySize:64}]]",
                            "BlockCipher:RC2-64-CFB[KeyLength:64, Mode:CFB]"),
                    // 101: RC2_ofb64_encrypt(buf, buf, 64, &r2, iv, &num);
                    finding(
                            "CipherContext{ValueAction:RC2-OFB}[CipherContext{ValueAction:RC2}[CipherContext{KeySize:64}]]",
                            "BlockCipher:RC2-64-OFB[KeyLength:64, Mode:OFB]"),
                    // 103: RC5_32_ecb_encrypt(buf, buf, &r5, 1);
                    finding(
                            "CipherContext{ValueAction:RC5-ECB}[CipherContext{ValueAction:RC5}[CipherContext{KeySize:80}]]",
                            "BlockCipher:RC5-80-ECB[KeyLength:80, Mode:ECB]"),
                    // 104: RC5_32_cbc_encrypt(buf, buf, 64, &r5, iv, 1);
                    finding(
                            "CipherContext{ValueAction:RC5-CBC}[CipherContext{ValueAction:RC5}[CipherContext{KeySize:80}]]",
                            "BlockCipher:RC5-80-CBC[KeyLength:80, Mode:CBC]"),
                    // 105: RC5_32_cfb64_encrypt(buf, buf, 64, &r5, iv, &num, 1);
                    finding(
                            "CipherContext{ValueAction:RC5-CFB}[CipherContext{ValueAction:RC5}[CipherContext{KeySize:80}]]",
                            "BlockCipher:RC5-80-CFB[KeyLength:80, Mode:CFB]"),
                    // 106: RC5_32_ofb64_encrypt(buf, buf, 64, &r5, iv, &num);
                    finding(
                            "CipherContext{ValueAction:RC5-OFB}[CipherContext{ValueAction:RC5}[CipherContext{KeySize:80}]]",
                            "BlockCipher:RC5-80-OFB[KeyLength:80, Mode:OFB]"),
                    // 115: CAST_ecb_encrypt(buf, buf, &ck, 1);
                    finding(
                            "CipherContext{ValueAction:CAST5-ECB}[CipherContext{ValueAction:CAST5}[CipherContext{KeySize:80}]]",
                            "BlockCipher:CAST5-80-ECB[BlockSize:64, KeyLength:80, Mode:ECB]"),
                    // 116: CAST_cbc_encrypt(buf, buf, 64, &ck, iv, 1);
                    finding(
                            "CipherContext{ValueAction:CAST5-CBC}[CipherContext{ValueAction:CAST5}[CipherContext{KeySize:80}]]",
                            "BlockCipher:CAST5-80-CBC[BlockSize:64, KeyLength:80, Mode:CBC]"),
                    // 117: CAST_cfb64_encrypt(buf, buf, 64, &ck, iv, &num, 1);
                    finding(
                            "CipherContext{ValueAction:CAST5-CFB}[CipherContext{ValueAction:CAST5}[CipherContext{KeySize:80}]]",
                            "BlockCipher:CAST5-80-CFB[BlockSize:64, KeyLength:80, Mode:CFB]"),
                    // 118: CAST_ofb64_encrypt(buf, buf, 64, &ck, iv, &num);
                    finding(
                            "CipherContext{ValueAction:CAST5-OFB}[CipherContext{ValueAction:CAST5}[CipherContext{KeySize:80}]]",
                            "BlockCipher:CAST5-80-OFB[BlockSize:64, KeyLength:80, Mode:OFB]"),
                    // 128: IDEA_ecb_encrypt(buf, buf, &ik);
                    finding(
                            "CipherContext{ValueAction:IDEA-ECB}[CipherContext{ValueAction:IDEA}, CipherContext{ValueAction:IDEA}]",
                            "BlockCipher:IDEA-ECB[Mode:ECB]"),
                    // 129: IDEA_cbc_encrypt(buf, buf, 64, &ik, iv, 1);
                    finding(
                            "CipherContext{ValueAction:IDEA-CBC}[CipherContext{ValueAction:IDEA}, CipherContext{ValueAction:IDEA}]",
                            "BlockCipher:IDEA-CBC[Mode:CBC]"),
                    // 130: IDEA_cfb64_encrypt(buf, buf, 64, &ik, iv, &num, 1);
                    finding(
                            "CipherContext{ValueAction:IDEA-CFB}[CipherContext{ValueAction:IDEA}, CipherContext{ValueAction:IDEA}]",
                            "BlockCipher:IDEA-CFB[Mode:CFB]"),
                    // 131: IDEA_ofb64_encrypt(buf, buf, 64, &ik, iv, &num);
                    finding(
                            "CipherContext{ValueAction:IDEA-OFB}[CipherContext{ValueAction:IDEA}, CipherContext{ValueAction:IDEA}]",
                            "BlockCipher:IDEA-OFB[Mode:OFB]"),
                    // 141: Camellia_ecb_encrypt(buf, buf, &cam, 1);
                    finding(
                            "CipherContext{ValueAction:CAMELLIA-ECB}[CipherContext{ValueAction:CAMELLIA}[CipherContext{KeySize:256}]]",
                            "BlockCipher:CAMELLIA-256-ECB[KeyLength:256, Mode:ECB]"),
                    // 142: Camellia_cbc_encrypt(buf, buf, 64, &cam, iv, 1);
                    finding(
                            "CipherContext{ValueAction:CAMELLIA-CBC}[CipherContext{ValueAction:CAMELLIA}[CipherContext{KeySize:256}]]",
                            "BlockCipher:CAMELLIA-256-CBC[KeyLength:256, Mode:CBC]"),
                    // 143: Camellia_cfb128_encrypt(buf, buf, 64, &cam, iv, &num, 1);
                    finding(
                            "CipherContext{ValueAction:CAMELLIA-CFB128}[CipherContext{ValueAction:CAMELLIA}[CipherContext{KeySize:256}]]",
                            "BlockCipher:CAMELLIA-256-CFB128[KeyLength:256, Mode:CFB128]"),
                    // 144: Camellia_cfb1_encrypt(buf, buf, 64, &cam, iv, &num, 1);
                    finding(
                            "CipherContext{ValueAction:CAMELLIA-CFB1}[CipherContext{ValueAction:CAMELLIA}[CipherContext{KeySize:256}]]",
                            "BlockCipher:CAMELLIA-256-CFB1[KeyLength:256, Mode:CFB1]"),
                    // 145: Camellia_cfb8_encrypt(buf, buf, 64, &cam, iv, &num, 1);
                    finding(
                            "CipherContext{ValueAction:CAMELLIA-CFB8}[CipherContext{ValueAction:CAMELLIA}[CipherContext{KeySize:256}]]",
                            "BlockCipher:CAMELLIA-256-CFB8[KeyLength:256, Mode:CFB8]"),
                    // 146: Camellia_ofb128_encrypt(buf, buf, 64, &cam, iv, &num);
                    finding(
                            "CipherContext{ValueAction:CAMELLIA-OFB}[CipherContext{ValueAction:CAMELLIA}[CipherContext{KeySize:256}]]",
                            "BlockCipher:CAMELLIA-256-OFB[KeyLength:256, Mode:OFB]"),
                    // 147: Camellia_ctr128_encrypt(buf, buf, 64, &cam, iv, buf, &unum);
                    finding(
                            "CipherContext{ValueAction:CAMELLIA-CTR}[CipherContext{ValueAction:CAMELLIA}[CipherContext{KeySize:256}]]",
                            "BlockCipher:CAMELLIA-256-CTR[KeyLength:256, Mode:CTR]"),
                    // 156: SEED_ecb_encrypt(buf, buf, &sk, 1);
                    finding(
                            "CipherContext{ValueAction:SEED-ECB}[CipherContext{ValueAction:SEED}]",
                            "BlockCipher:SEED-128-ECB[BlockSize:128, KeyLength:128, Mode:ECB]"),
                    // 157: SEED_cbc_encrypt(buf, buf, 64, &sk, iv, 1);
                    finding(
                            "CipherContext{ValueAction:SEED-CBC}[CipherContext{ValueAction:SEED}]",
                            "BlockCipher:SEED-128-CBC[BlockSize:128, KeyLength:128, Mode:CBC]"),
                    // 158: SEED_cfb128_encrypt(buf, buf, 64, &sk, iv, &num, 1);
                    finding(
                            "CipherContext{ValueAction:SEED-CFB}[CipherContext{ValueAction:SEED}]",
                            "BlockCipher:SEED-128-CFB[BlockSize:128, KeyLength:128, Mode:CFB]"),
                    // 159: SEED_ofb128_encrypt(buf, buf, 64, &sk, iv, &num);
                    finding(
                            "CipherContext{ValueAction:SEED-OFB}[CipherContext{ValueAction:SEED}]",
                            "BlockCipher:SEED-128-OFB[BlockSize:128, KeyLength:128, Mode:OFB]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/legacy/OpenSSLLegacyCipherTestFile.cc", this);
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
