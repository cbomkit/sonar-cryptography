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
 * Covers EVP cipher detection rules in {@link OpenSSLEvpCipher}.
 *
 * <p>Every cipher family (AES, ARIA, Camellia, SM4, DES/DESede, Blowfish, CAST5, RC2, RC4, RC5,
 * IDEA, SEED, ChaCha20, ChaCha20-Poly1305) and the EVP, CMS and PKCS#7 init, fetch and encryption
 * functions. {@code EVP_enc_null()}, and the init and encryption functions given a {@code NULL}
 * cipher, name no algorithm and are not reported.
 */
class OpenSSLEvpCipherTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 9: EVP_aes_128_cbc();
                    finding(
                            "CipherContext{ValueAction:AES-128-CBC}",
                            "BlockCipher:AES-128-CBC[BlockSize:128, KeyLength:128, Mode:CBC, "
                                    + "Oid:2.16.840.1.101.3.4.1.2]"),
                    // 10: EVP_aes_128_ecb();
                    finding(
                            "CipherContext{ValueAction:AES-128-ECB}",
                            "BlockCipher:AES-128-ECB[BlockSize:128, KeyLength:128, Mode:ECB, "
                                    + "Oid:2.16.840.1.101.3.4.1.1]"),
                    // 11: EVP_aes_128_gcm();
                    finding(
                            "CipherContext{ValueAction:AES-128-GCM}",
                            "AuthenticatedEncryption:AES-128-GCM[BlockSize:128, KeyLength:128, Mode:GCM, "
                                    + "Oid:2.16.840.1.101.3.4.1.6]"),
                    // 12: EVP_aes_128_ctr();
                    finding(
                            "CipherContext{ValueAction:AES-128-CTR}",
                            "BlockCipher:AES-128-CTR[BlockSize:128, KeyLength:128, Mode:CTR, "
                                    + "Oid:2.16.840.1.101.3.4.1]"),
                    // 13: EVP_aes_128_ccm();
                    finding(
                            "CipherContext{ValueAction:AES-128-CCM}",
                            "AuthenticatedEncryption:AES-128-CCM[BlockSize:128, KeyLength:128, Mode:CCM, "
                                    + "Oid:2.16.840.1.101.3.4.1.7]"),
                    // 14: EVP_aes_128_cfb128();
                    finding(
                            "CipherContext{ValueAction:AES-128-CFB}",
                            "BlockCipher:AES-128-CFB[BlockSize:128, KeyLength:128, Mode:CFB, "
                                    + "Oid:2.16.840.1.101.3.4.1.4]"),
                    // 15: EVP_aes_128_cfb1();
                    finding(
                            "CipherContext{ValueAction:AES-128-CFB1}",
                            "BlockCipher:AES-128-CFB1[BlockSize:128, KeyLength:128, Mode:CFB1, "
                                    + "Oid:2.16.840.1.101.3.4.1]"),
                    // 16: EVP_aes_128_cfb8();
                    finding(
                            "CipherContext{ValueAction:AES-128-CFB8}",
                            "BlockCipher:AES-128-CFB8[BlockSize:128, KeyLength:128, Mode:CFB8, "
                                    + "Oid:2.16.840.1.101.3.4.1]"),
                    // 17: EVP_aes_128_ofb();
                    finding(
                            "CipherContext{ValueAction:AES-128-OFB}",
                            "BlockCipher:AES-128-OFB[BlockSize:128, KeyLength:128, Mode:OFB, "
                                    + "Oid:2.16.840.1.101.3.4.1.3]"),
                    // 18: EVP_aes_128_xts();
                    finding(
                            "CipherContext{ValueAction:AES-128-XTS}",
                            "BlockCipher:AES-128-XTS[BlockSize:128, KeyLength:128, Mode:XTS, "
                                    + "Oid:2.16.840.1.101.3.4.1]"),
                    // 19: EVP_aes_128_ocb();
                    finding(
                            "CipherContext{ValueAction:AES-128-OCB}",
                            "BlockCipher:AES-128-OCB[BlockSize:128, KeyLength:128, Mode:OCB, "
                                    + "Oid:2.16.840.1.101.3.4.1]"),
                    // 20: EVP_aes_128_wrap();
                    finding(
                            "CipherContext{ValueAction:AES-128-WRAP}",
                            "BlockCipher:AES-128-WRAP[BlockSize:128, KeyLength:128, Mode:WRAP, "
                                    + "Oid:2.16.840.1.101.3.4.1.5]"),
                    // 21: EVP_aes_128_wrap_pad();
                    finding(
                            "CipherContext{ValueAction:AES-128-WRAP-PAD}",
                            "BlockCipher:AES-128-WRAP-PAD[BlockSize:128, KeyLength:128, Mode:WRAP-PAD, "
                                    + "Oid:2.16.840.1.101.3.4.1.8]"),
                    // 22: EVP_aes_192_cbc();
                    finding(
                            "CipherContext{ValueAction:AES-192-CBC}",
                            "BlockCipher:AES-192-CBC[BlockSize:128, KeyLength:192, Mode:CBC, "
                                    + "Oid:2.16.840.1.101.3.4.1.22]"),
                    // 23: EVP_aes_192_ecb();
                    finding(
                            "CipherContext{ValueAction:AES-192-ECB}",
                            "BlockCipher:AES-192-ECB[BlockSize:128, KeyLength:192, Mode:ECB, "
                                    + "Oid:2.16.840.1.101.3.4.1.21]"),
                    // 24: EVP_aes_192_gcm();
                    finding(
                            "CipherContext{ValueAction:AES-192-GCM}",
                            "AuthenticatedEncryption:AES-192-GCM[BlockSize:128, KeyLength:192, Mode:GCM, "
                                    + "Oid:2.16.840.1.101.3.4.1.26]"),
                    // 25: EVP_aes_192_ctr();
                    finding(
                            "CipherContext{ValueAction:AES-192-CTR}",
                            "BlockCipher:AES-192-CTR[BlockSize:128, KeyLength:192, Mode:CTR, "
                                    + "Oid:2.16.840.1.101.3.4.1.2]"),
                    // 26: EVP_aes_192_ccm();
                    finding(
                            "CipherContext{ValueAction:AES-192-CCM}",
                            "AuthenticatedEncryption:AES-192-CCM[BlockSize:128, KeyLength:192, Mode:CCM, "
                                    + "Oid:2.16.840.1.101.3.4.1.27]"),
                    // 27: EVP_aes_192_cfb128();
                    finding(
                            "CipherContext{ValueAction:AES-192-CFB}",
                            "BlockCipher:AES-192-CFB[BlockSize:128, KeyLength:192, Mode:CFB, "
                                    + "Oid:2.16.840.1.101.3.4.1.24]"),
                    // 28: EVP_aes_192_cfb1();
                    finding(
                            "CipherContext{ValueAction:AES-192-CFB1}",
                            "BlockCipher:AES-192-CFB1[BlockSize:128, KeyLength:192, Mode:CFB1, "
                                    + "Oid:2.16.840.1.101.3.4.1.2]"),
                    // 29: EVP_aes_192_cfb8();
                    finding(
                            "CipherContext{ValueAction:AES-192-CFB8}",
                            "BlockCipher:AES-192-CFB8[BlockSize:128, KeyLength:192, Mode:CFB8, "
                                    + "Oid:2.16.840.1.101.3.4.1.2]"),
                    // 30: EVP_aes_192_ofb();
                    finding(
                            "CipherContext{ValueAction:AES-192-OFB}",
                            "BlockCipher:AES-192-OFB[BlockSize:128, KeyLength:192, Mode:OFB, "
                                    + "Oid:2.16.840.1.101.3.4.1.23]"),
                    // 31: EVP_aes_192_ocb();
                    finding(
                            "CipherContext{ValueAction:AES-192-OCB}",
                            "BlockCipher:AES-192-OCB[BlockSize:128, KeyLength:192, Mode:OCB, "
                                    + "Oid:2.16.840.1.101.3.4.1.2]"),
                    // 32: EVP_aes_192_wrap();
                    finding(
                            "CipherContext{ValueAction:AES-192-WRAP}",
                            "BlockCipher:AES-192-WRAP[BlockSize:128, KeyLength:192, Mode:WRAP, "
                                    + "Oid:2.16.840.1.101.3.4.1.25]"),
                    // 33: EVP_aes_192_wrap_pad();
                    finding(
                            "CipherContext{ValueAction:AES-192-WRAP-PAD}",
                            "BlockCipher:AES-192-WRAP-PAD[BlockSize:128, KeyLength:192, Mode:WRAP-PAD, "
                                    + "Oid:2.16.840.1.101.3.4.1.28]"),
                    // 34: EVP_aes_256_cbc();
                    finding(
                            "CipherContext{ValueAction:AES-256-CBC}",
                            "BlockCipher:AES-256-CBC[BlockSize:128, KeyLength:256, Mode:CBC, "
                                    + "Oid:2.16.840.1.101.3.4.1.42]"),
                    // 35: EVP_aes_256_ecb();
                    finding(
                            "CipherContext{ValueAction:AES-256-ECB}",
                            "BlockCipher:AES-256-ECB[BlockSize:128, KeyLength:256, Mode:ECB, "
                                    + "Oid:2.16.840.1.101.3.4.1.41]"),
                    // 36: EVP_aes_256_gcm();
                    finding(
                            "CipherContext{ValueAction:AES-256-GCM}",
                            "AuthenticatedEncryption:AES-256-GCM[BlockSize:128, KeyLength:256, Mode:GCM, "
                                    + "Oid:2.16.840.1.101.3.4.1.46]"),
                    // 37: EVP_aes_256_ctr();
                    finding(
                            "CipherContext{ValueAction:AES-256-CTR}",
                            "BlockCipher:AES-256-CTR[BlockSize:128, KeyLength:256, Mode:CTR, "
                                    + "Oid:2.16.840.1.101.3.4.1.4]"),
                    // 38: EVP_aes_256_ccm();
                    finding(
                            "CipherContext{ValueAction:AES-256-CCM}",
                            "AuthenticatedEncryption:AES-256-CCM[BlockSize:128, KeyLength:256, Mode:CCM, "
                                    + "Oid:2.16.840.1.101.3.4.1.47]"),
                    // 39: EVP_aes_256_cfb128();
                    finding(
                            "CipherContext{ValueAction:AES-256-CFB}",
                            "BlockCipher:AES-256-CFB[BlockSize:128, KeyLength:256, Mode:CFB, "
                                    + "Oid:2.16.840.1.101.3.4.1.44]"),
                    // 40: EVP_aes_256_cfb1();
                    finding(
                            "CipherContext{ValueAction:AES-256-CFB1}",
                            "BlockCipher:AES-256-CFB1[BlockSize:128, KeyLength:256, Mode:CFB1, "
                                    + "Oid:2.16.840.1.101.3.4.1.4]"),
                    // 41: EVP_aes_256_cfb8();
                    finding(
                            "CipherContext{ValueAction:AES-256-CFB8}",
                            "BlockCipher:AES-256-CFB8[BlockSize:128, KeyLength:256, Mode:CFB8, "
                                    + "Oid:2.16.840.1.101.3.4.1.4]"),
                    // 42: EVP_aes_256_ofb();
                    finding(
                            "CipherContext{ValueAction:AES-256-OFB}",
                            "BlockCipher:AES-256-OFB[BlockSize:128, KeyLength:256, Mode:OFB, "
                                    + "Oid:2.16.840.1.101.3.4.1.43]"),
                    // 43: EVP_aes_256_xts();
                    finding(
                            "CipherContext{ValueAction:AES-256-XTS}",
                            "BlockCipher:AES-256-XTS[BlockSize:128, KeyLength:256, Mode:XTS, "
                                    + "Oid:2.16.840.1.101.3.4.1.4]"),
                    // 44: EVP_aes_256_ocb();
                    finding(
                            "CipherContext{ValueAction:AES-256-OCB}",
                            "BlockCipher:AES-256-OCB[BlockSize:128, KeyLength:256, Mode:OCB, "
                                    + "Oid:2.16.840.1.101.3.4.1.4]"),
                    // 45: EVP_aes_256_wrap();
                    finding(
                            "CipherContext{ValueAction:AES-256-WRAP}",
                            "BlockCipher:AES-256-WRAP[BlockSize:128, KeyLength:256, Mode:WRAP, "
                                    + "Oid:2.16.840.1.101.3.4.1.45]"),
                    // 46: EVP_aes_256_wrap_pad();
                    finding(
                            "CipherContext{ValueAction:AES-256-WRAP-PAD}",
                            "BlockCipher:AES-256-WRAP-PAD[BlockSize:128, KeyLength:256, Mode:WRAP-PAD, "
                                    + "Oid:2.16.840.1.101.3.4.1.48]"),
                    // 47: EVP_camellia_128_ecb();
                    finding(
                            "CipherContext{ValueAction:CAMELLIA-128-ECB}",
                            "BlockCipher:CAMELLIA-128-ECB[KeyLength:128, Mode:ECB]"),
                    // 48: EVP_camellia_128_cbc();
                    finding(
                            "CipherContext{ValueAction:CAMELLIA-128-CBC}",
                            "BlockCipher:CAMELLIA-128-CBC[KeyLength:128, Mode:CBC]"),
                    // 49: EVP_camellia_128_cfb128();
                    finding(
                            "CipherContext{ValueAction:CAMELLIA-128-CFB}",
                            "BlockCipher:CAMELLIA-128-CFB[KeyLength:128, Mode:CFB]"),
                    // 50: EVP_camellia_128_cfb1();
                    finding(
                            "CipherContext{ValueAction:CAMELLIA-128-CFB1}",
                            "BlockCipher:CAMELLIA-128-CFB1[KeyLength:128, Mode:CFB1]"),
                    // 51: EVP_camellia_128_cfb8();
                    finding(
                            "CipherContext{ValueAction:CAMELLIA-128-CFB8}",
                            "BlockCipher:CAMELLIA-128-CFB8[KeyLength:128, Mode:CFB8]"),
                    // 52: EVP_camellia_128_ofb();
                    finding(
                            "CipherContext{ValueAction:CAMELLIA-128-OFB}",
                            "BlockCipher:CAMELLIA-128-OFB[KeyLength:128, Mode:OFB]"),
                    // 53: EVP_camellia_128_ctr();
                    finding(
                            "CipherContext{ValueAction:CAMELLIA-128-CTR}",
                            "BlockCipher:CAMELLIA-128-CTR[KeyLength:128, Mode:CTR]"),
                    // 54: EVP_camellia_192_ecb();
                    finding(
                            "CipherContext{ValueAction:CAMELLIA-192-ECB}",
                            "BlockCipher:CAMELLIA-192-ECB[KeyLength:192, Mode:ECB]"),
                    // 55: EVP_camellia_192_cbc();
                    finding(
                            "CipherContext{ValueAction:CAMELLIA-192-CBC}",
                            "BlockCipher:CAMELLIA-192-CBC[KeyLength:192, Mode:CBC]"),
                    // 56: EVP_camellia_192_cfb128();
                    finding(
                            "CipherContext{ValueAction:CAMELLIA-192-CFB}",
                            "BlockCipher:CAMELLIA-192-CFB[KeyLength:192, Mode:CFB]"),
                    // 57: EVP_camellia_192_cfb1();
                    finding(
                            "CipherContext{ValueAction:CAMELLIA-192-CFB1}",
                            "BlockCipher:CAMELLIA-192-CFB1[KeyLength:192, Mode:CFB1]"),
                    // 58: EVP_camellia_192_cfb8();
                    finding(
                            "CipherContext{ValueAction:CAMELLIA-192-CFB8}",
                            "BlockCipher:CAMELLIA-192-CFB8[KeyLength:192, Mode:CFB8]"),
                    // 59: EVP_camellia_192_ofb();
                    finding(
                            "CipherContext{ValueAction:CAMELLIA-192-OFB}",
                            "BlockCipher:CAMELLIA-192-OFB[KeyLength:192, Mode:OFB]"),
                    // 60: EVP_camellia_192_ctr();
                    finding(
                            "CipherContext{ValueAction:CAMELLIA-192-CTR}",
                            "BlockCipher:CAMELLIA-192-CTR[KeyLength:192, Mode:CTR]"),
                    // 61: EVP_camellia_256_ecb();
                    finding(
                            "CipherContext{ValueAction:CAMELLIA-256-ECB}",
                            "BlockCipher:CAMELLIA-256-ECB[KeyLength:256, Mode:ECB]"),
                    // 62: EVP_camellia_256_cbc();
                    finding(
                            "CipherContext{ValueAction:CAMELLIA-256-CBC}",
                            "BlockCipher:CAMELLIA-256-CBC[KeyLength:256, Mode:CBC]"),
                    // 63: EVP_camellia_256_cfb128();
                    finding(
                            "CipherContext{ValueAction:CAMELLIA-256-CFB}",
                            "BlockCipher:CAMELLIA-256-CFB[KeyLength:256, Mode:CFB]"),
                    // 64: EVP_camellia_256_cfb1();
                    finding(
                            "CipherContext{ValueAction:CAMELLIA-256-CFB1}",
                            "BlockCipher:CAMELLIA-256-CFB1[KeyLength:256, Mode:CFB1]"),
                    // 65: EVP_camellia_256_cfb8();
                    finding(
                            "CipherContext{ValueAction:CAMELLIA-256-CFB8}",
                            "BlockCipher:CAMELLIA-256-CFB8[KeyLength:256, Mode:CFB8]"),
                    // 66: EVP_camellia_256_ofb();
                    finding(
                            "CipherContext{ValueAction:CAMELLIA-256-OFB}",
                            "BlockCipher:CAMELLIA-256-OFB[KeyLength:256, Mode:OFB]"),
                    // 67: EVP_camellia_256_ctr();
                    finding(
                            "CipherContext{ValueAction:CAMELLIA-256-CTR}",
                            "BlockCipher:CAMELLIA-256-CTR[KeyLength:256, Mode:CTR]"),
                    // 68: EVP_aria_128_ecb();
                    finding(
                            "CipherContext{ValueAction:ARIA-128-ECB}",
                            "BlockCipher:ARIA-128-ECB[KeyLength:128, Mode:ECB]"),
                    // 69: EVP_aria_128_cbc();
                    finding(
                            "CipherContext{ValueAction:ARIA-128-CBC}",
                            "BlockCipher:ARIA-128-CBC[KeyLength:128, Mode:CBC]"),
                    // 70: EVP_aria_128_cfb128();
                    finding(
                            "CipherContext{ValueAction:ARIA-128-CFB}",
                            "BlockCipher:ARIA-128-CFB[KeyLength:128, Mode:CFB]"),
                    // 71: EVP_aria_128_cfb1();
                    finding(
                            "CipherContext{ValueAction:ARIA-128-CFB1}",
                            "BlockCipher:ARIA-128-CFB1[KeyLength:128, Mode:CFB1]"),
                    // 72: EVP_aria_128_cfb8();
                    finding(
                            "CipherContext{ValueAction:ARIA-128-CFB8}",
                            "BlockCipher:ARIA-128-CFB8[KeyLength:128, Mode:CFB8]"),
                    // 73: EVP_aria_128_ofb();
                    finding(
                            "CipherContext{ValueAction:ARIA-128-OFB}",
                            "BlockCipher:ARIA-128-OFB[KeyLength:128, Mode:OFB]"),
                    // 74: EVP_aria_128_ctr();
                    finding(
                            "CipherContext{ValueAction:ARIA-128-CTR}",
                            "BlockCipher:ARIA-128-CTR[KeyLength:128, Mode:CTR]"),
                    // 75: EVP_aria_128_gcm();
                    finding(
                            "CipherContext{ValueAction:ARIA-128-GCM}",
                            "BlockCipher:ARIA-128-GCM[KeyLength:128, Mode:GCM]"),
                    // 76: EVP_aria_128_ccm();
                    finding(
                            "CipherContext{ValueAction:ARIA-128-CCM}",
                            "BlockCipher:ARIA-128-CCM[KeyLength:128, Mode:CCM]"),
                    // 77: EVP_aria_192_ecb();
                    finding(
                            "CipherContext{ValueAction:ARIA-192-ECB}",
                            "BlockCipher:ARIA-192-ECB[KeyLength:192, Mode:ECB]"),
                    // 78: EVP_aria_192_cbc();
                    finding(
                            "CipherContext{ValueAction:ARIA-192-CBC}",
                            "BlockCipher:ARIA-192-CBC[KeyLength:192, Mode:CBC]"),
                    // 79: EVP_aria_192_cfb128();
                    finding(
                            "CipherContext{ValueAction:ARIA-192-CFB}",
                            "BlockCipher:ARIA-192-CFB[KeyLength:192, Mode:CFB]"),
                    // 80: EVP_aria_192_cfb1();
                    finding(
                            "CipherContext{ValueAction:ARIA-192-CFB1}",
                            "BlockCipher:ARIA-192-CFB1[KeyLength:192, Mode:CFB1]"),
                    // 81: EVP_aria_192_cfb8();
                    finding(
                            "CipherContext{ValueAction:ARIA-192-CFB8}",
                            "BlockCipher:ARIA-192-CFB8[KeyLength:192, Mode:CFB8]"),
                    // 82: EVP_aria_192_ofb();
                    finding(
                            "CipherContext{ValueAction:ARIA-192-OFB}",
                            "BlockCipher:ARIA-192-OFB[KeyLength:192, Mode:OFB]"),
                    // 83: EVP_aria_192_ctr();
                    finding(
                            "CipherContext{ValueAction:ARIA-192-CTR}",
                            "BlockCipher:ARIA-192-CTR[KeyLength:192, Mode:CTR]"),
                    // 84: EVP_aria_192_gcm();
                    finding(
                            "CipherContext{ValueAction:ARIA-192-GCM}",
                            "BlockCipher:ARIA-192-GCM[KeyLength:192, Mode:GCM]"),
                    // 85: EVP_aria_192_ccm();
                    finding(
                            "CipherContext{ValueAction:ARIA-192-CCM}",
                            "BlockCipher:ARIA-192-CCM[KeyLength:192, Mode:CCM]"),
                    // 86: EVP_aria_256_ecb();
                    finding(
                            "CipherContext{ValueAction:ARIA-256-ECB}",
                            "BlockCipher:ARIA-256-ECB[KeyLength:256, Mode:ECB]"),
                    // 87: EVP_aria_256_cbc();
                    finding(
                            "CipherContext{ValueAction:ARIA-256-CBC}",
                            "BlockCipher:ARIA-256-CBC[KeyLength:256, Mode:CBC]"),
                    // 88: EVP_aria_256_cfb128();
                    finding(
                            "CipherContext{ValueAction:ARIA-256-CFB}",
                            "BlockCipher:ARIA-256-CFB[KeyLength:256, Mode:CFB]"),
                    // 89: EVP_aria_256_cfb1();
                    finding(
                            "CipherContext{ValueAction:ARIA-256-CFB1}",
                            "BlockCipher:ARIA-256-CFB1[KeyLength:256, Mode:CFB1]"),
                    // 90: EVP_aria_256_cfb8();
                    finding(
                            "CipherContext{ValueAction:ARIA-256-CFB8}",
                            "BlockCipher:ARIA-256-CFB8[KeyLength:256, Mode:CFB8]"),
                    // 91: EVP_aria_256_ofb();
                    finding(
                            "CipherContext{ValueAction:ARIA-256-OFB}",
                            "BlockCipher:ARIA-256-OFB[KeyLength:256, Mode:OFB]"),
                    // 92: EVP_aria_256_ctr();
                    finding(
                            "CipherContext{ValueAction:ARIA-256-CTR}",
                            "BlockCipher:ARIA-256-CTR[KeyLength:256, Mode:CTR]"),
                    // 93: EVP_aria_256_gcm();
                    finding(
                            "CipherContext{ValueAction:ARIA-256-GCM}",
                            "BlockCipher:ARIA-256-GCM[KeyLength:256, Mode:GCM]"),
                    // 94: EVP_aria_256_ccm();
                    finding(
                            "CipherContext{ValueAction:ARIA-256-CCM}",
                            "BlockCipher:ARIA-256-CCM[KeyLength:256, Mode:CCM]"),
                    // 95: EVP_sm4_ecb();
                    finding("CipherContext{ValueAction:SM4-ECB}", "BlockCipher:SM4-ECB[Mode:ECB]"),
                    // 96: EVP_sm4_cbc();
                    finding("CipherContext{ValueAction:SM4-CBC}", "BlockCipher:SM4-CBC[Mode:CBC]"),
                    // 97: EVP_sm4_cfb128();
                    finding("CipherContext{ValueAction:SM4-CFB}", "BlockCipher:SM4-CFB[Mode:CFB]"),
                    // 98: EVP_sm4_ofb();
                    finding("CipherContext{ValueAction:SM4-OFB}", "BlockCipher:SM4-OFB[Mode:OFB]"),
                    // 99: EVP_sm4_ctr();
                    finding("CipherContext{ValueAction:SM4-CTR}", "BlockCipher:SM4-CTR[Mode:CTR]"),
                    // 100: EVP_des_cbc();
                    finding(
                            "CipherContext{ValueAction:DES-CBC}",
                            "BlockCipher:DES-56-CBC[BlockSize:64, KeyLength:56, Mode:CBC]"),
                    // 101: EVP_des_ecb();
                    finding(
                            "CipherContext{ValueAction:DES-ECB}",
                            "BlockCipher:DES-56-ECB[BlockSize:64, KeyLength:56, Mode:ECB]"),
                    // 102: EVP_des_ede3_cbc();
                    finding(
                            "CipherContext{ValueAction:DESede3-CBC}",
                            "BlockCipher:DESede168-CBC[BlockSize:64, KeyLength:168, Mode:CBC]"),
                    // 103: EVP_des_cfb64();
                    finding(
                            "CipherContext{ValueAction:DES-CFB}",
                            "BlockCipher:DES-56-CFB[BlockSize:64, KeyLength:56, Mode:CFB]"),
                    // 104: EVP_des_cfb1();
                    finding(
                            "CipherContext{ValueAction:DES-CFB1}",
                            "BlockCipher:DES-56-CFB1[BlockSize:64, KeyLength:56, Mode:CFB1]"),
                    // 105: EVP_des_cfb8();
                    finding(
                            "CipherContext{ValueAction:DES-CFB8}",
                            "BlockCipher:DES-56-CFB8[BlockSize:64, KeyLength:56, Mode:CFB8]"),
                    // 106: EVP_des_ofb();
                    finding(
                            "CipherContext{ValueAction:DES-OFB}",
                            "BlockCipher:DES-56-OFB[BlockSize:64, KeyLength:56, Mode:OFB]"),
                    // 107: EVP_des_ede();
                    finding(
                            "CipherContext{ValueAction:DESede}",
                            "BlockCipher:DESede112[BlockSize:64, KeyLength:112]"),
                    // 108: EVP_des_ede_ecb();
                    finding(
                            "CipherContext{ValueAction:DESede-ECB}",
                            "BlockCipher:DESede112-ECB[BlockSize:64, KeyLength:112, Mode:ECB]"),
                    // 109: EVP_des_ede_cbc();
                    finding(
                            "CipherContext{ValueAction:DESede-CBC}",
                            "BlockCipher:DESede112-CBC[BlockSize:64, KeyLength:112, Mode:CBC]"),
                    // 110: EVP_des_ede_cfb64();
                    finding(
                            "CipherContext{ValueAction:DESede-CFB64}",
                            "BlockCipher:DESede112-CFB64[BlockSize:64, KeyLength:112, Mode:CFB64]"),
                    // 111: EVP_des_ede_ofb();
                    finding(
                            "CipherContext{ValueAction:DESede-OFB}",
                            "BlockCipher:DESede112-OFB[BlockSize:64, KeyLength:112, Mode:OFB]"),
                    // 112: EVP_des_ede3();
                    finding(
                            "CipherContext{ValueAction:DESede3}",
                            "BlockCipher:DESede168[BlockSize:64, KeyLength:168]"),
                    // 113: EVP_des_ede3_ecb();
                    finding(
                            "CipherContext{ValueAction:DESede3-ECB}",
                            "BlockCipher:DESede168-ECB[BlockSize:64, KeyLength:168, Mode:ECB]"),
                    // 114: EVP_des_ede3_cfb1();
                    finding(
                            "CipherContext{ValueAction:DESede3-CFB1}",
                            "BlockCipher:DESede168-CFB1[BlockSize:64, KeyLength:168, Mode:CFB1]"),
                    // 115: EVP_des_ede3_cfb8();
                    finding(
                            "CipherContext{ValueAction:DESede3-CFB8}",
                            "BlockCipher:DESede168-CFB8[BlockSize:64, KeyLength:168, Mode:CFB8]"),
                    // 116: EVP_des_ede3_cfb64();
                    finding(
                            "CipherContext{ValueAction:DESede3-CFB64}",
                            "BlockCipher:DESede168-CFB64[BlockSize:64, KeyLength:168, Mode:CFB64]"),
                    // 117: EVP_des_ede3_ofb();
                    finding(
                            "CipherContext{ValueAction:DESede3-OFB}",
                            "BlockCipher:DESede168-OFB[BlockSize:64, KeyLength:168, Mode:OFB]"),
                    // 118: EVP_desx_cbc();
                    finding(
                            "CipherContext{ValueAction:DESX-CBC}",
                            "BlockCipher:DESX-184-CBC[BlockSize:64, KeyLength:184, Mode:CBC]"),
                    // 119: EVP_bf_ecb();
                    finding(
                            "CipherContext{ValueAction:BLOWFISH-ECB}",
                            "BlockCipher:Blowfish-128-ECB[KeyLength:128, Mode:ECB]"),
                    // 120: EVP_bf_cbc();
                    finding(
                            "CipherContext{ValueAction:BLOWFISH-CBC}",
                            "BlockCipher:Blowfish-128-CBC[KeyLength:128, Mode:CBC]"),
                    // 121: EVP_bf_cfb64();
                    finding(
                            "CipherContext{ValueAction:BLOWFISH-CFB}",
                            "BlockCipher:Blowfish-128-CFB[KeyLength:128, Mode:CFB]"),
                    // 122: EVP_bf_ofb();
                    finding(
                            "CipherContext{ValueAction:BLOWFISH-OFB}",
                            "BlockCipher:Blowfish-128-OFB[KeyLength:128, Mode:OFB]"),
                    // 123: EVP_cast5_ecb();
                    finding(
                            "CipherContext{ValueAction:CAST5-ECB}",
                            "BlockCipher:CAST5-128-ECB[BlockSize:64, KeyLength:128, Mode:ECB]"),
                    // 124: EVP_cast5_cbc();
                    finding(
                            "CipherContext{ValueAction:CAST5-CBC}",
                            "BlockCipher:CAST5-128-CBC[BlockSize:64, KeyLength:128, Mode:CBC]"),
                    // 125: EVP_cast5_cfb64();
                    finding(
                            "CipherContext{ValueAction:CAST5-CFB}",
                            "BlockCipher:CAST5-128-CFB[BlockSize:64, KeyLength:128, Mode:CFB]"),
                    // 126: EVP_cast5_ofb();
                    finding(
                            "CipherContext{ValueAction:CAST5-OFB}",
                            "BlockCipher:CAST5-128-OFB[BlockSize:64, KeyLength:128, Mode:OFB]"),
                    // 127: EVP_rc2_ecb();
                    finding(
                            "CipherContext{ValueAction:RC2-ECB}",
                            "BlockCipher:RC2-128-ECB[KeyLength:128, Mode:ECB]"),
                    // 128: EVP_rc2_cbc();
                    finding(
                            "CipherContext{ValueAction:RC2-CBC}",
                            "BlockCipher:RC2-128-CBC[KeyLength:128, Mode:CBC]"),
                    // 129: EVP_rc2_cfb64();
                    finding(
                            "CipherContext{ValueAction:RC2-CFB}",
                            "BlockCipher:RC2-128-CFB[KeyLength:128, Mode:CFB]"),
                    // 130: EVP_rc2_ofb();
                    finding(
                            "CipherContext{ValueAction:RC2-OFB}",
                            "BlockCipher:RC2-128-OFB[KeyLength:128, Mode:OFB]"),
                    // 131: EVP_rc2_40_cbc();
                    finding(
                            "CipherContext{ValueAction:RC2-40-CBC}",
                            "BlockCipher:RC2-40-CBC[KeyLength:40, Mode:CBC]"),
                    // 132: EVP_rc2_64_cbc();
                    finding(
                            "CipherContext{ValueAction:RC2-64-CBC}",
                            "BlockCipher:RC2-64-CBC[KeyLength:64, Mode:CBC]"),
                    // 133: EVP_rc4();
                    finding("CipherContext{ValueAction:RC4}", "StreamCipher:RC4"),
                    // 134: EVP_rc4_40();
                    finding(
                            "CipherContext{ValueAction:RC4-40}",
                            "StreamCipher:RC4-40[KeyLength:40]"),
                    // 135: EVP_rc4_hmac_md5();
                    finding("CipherContext{ValueAction:RC4-HMAC-MD5}", "StreamCipher:RC4"),
                    // 136: EVP_rc5_32_12_16_ecb();
                    finding(
                            "CipherContext{ValueAction:RC5-ECB}",
                            "BlockCipher:RC5-128-ECB[KeyLength:128, Mode:ECB]"),
                    // 137: EVP_rc5_32_12_16_cbc();
                    finding(
                            "CipherContext{ValueAction:RC5-CBC}",
                            "BlockCipher:RC5-128-CBC[KeyLength:128, Mode:CBC]"),
                    // 138: EVP_rc5_32_12_16_cfb64();
                    finding(
                            "CipherContext{ValueAction:RC5-CFB}",
                            "BlockCipher:RC5-128-CFB[KeyLength:128, Mode:CFB]"),
                    // 139: EVP_rc5_32_12_16_ofb();
                    finding(
                            "CipherContext{ValueAction:RC5-OFB}",
                            "BlockCipher:RC5-128-OFB[KeyLength:128, Mode:OFB]"),
                    // 140: EVP_idea_ecb();
                    finding(
                            "CipherContext{ValueAction:IDEA-ECB}",
                            "BlockCipher:IDEA-ECB[Mode:ECB]"),
                    // 141: EVP_idea_cbc();
                    finding(
                            "CipherContext{ValueAction:IDEA-CBC}",
                            "BlockCipher:IDEA-CBC[Mode:CBC]"),
                    // 142: EVP_idea_cfb64();
                    finding(
                            "CipherContext{ValueAction:IDEA-CFB}",
                            "BlockCipher:IDEA-CFB[Mode:CFB]"),
                    // 143: EVP_idea_ofb();
                    finding(
                            "CipherContext{ValueAction:IDEA-OFB}",
                            "BlockCipher:IDEA-OFB[Mode:OFB]"),
                    // 144: EVP_seed_ecb();
                    finding(
                            "CipherContext{ValueAction:SEED-ECB}",
                            "BlockCipher:SEED-128-ECB[BlockSize:128, KeyLength:128, Mode:ECB]"),
                    // 145: EVP_seed_cbc();
                    finding(
                            "CipherContext{ValueAction:SEED-CBC}",
                            "BlockCipher:SEED-128-CBC[BlockSize:128, KeyLength:128, Mode:CBC]"),
                    // 146: EVP_seed_cfb128();
                    finding(
                            "CipherContext{ValueAction:SEED-CFB}",
                            "BlockCipher:SEED-128-CFB[BlockSize:128, KeyLength:128, Mode:CFB]"),
                    // 147: EVP_seed_ofb();
                    finding(
                            "CipherContext{ValueAction:SEED-OFB}",
                            "BlockCipher:SEED-128-OFB[BlockSize:128, KeyLength:128, Mode:OFB]"),
                    // 148: EVP_chacha20();
                    finding("CipherContext{ValueAction:ChaCha20}", "StreamCipher:ChaCha20"),
                    // 149: EVP_chacha20_poly1305();
                    finding(
                            "CipherContext{ValueAction:ChaCha20-Poly1305}",
                            "AuthenticatedEncryption:ChaCha20-Poly1305[MessageDigest:Poly1305[Digest:DIGEST]]"),
                    // 150: EVP_aes_128_cbc_hmac_sha1();
                    finding(
                            "CipherContext{ValueAction:AES-128-CBC-HMAC-SHA1}",
                            "BlockCipher:AES-128-CBC-HMAC-SHA1[BlockSize:128, KeyLength:128, "
                                    + "Mode:CBC-HMAC-SHA1, Oid:2.16.840.1.101.3.4.1]"),
                    // 151: EVP_aes_256_cbc_hmac_sha1();
                    finding(
                            "CipherContext{ValueAction:AES-256-CBC-HMAC-SHA1}",
                            "BlockCipher:AES-256-CBC-HMAC-SHA1[BlockSize:128, KeyLength:256, "
                                    + "Mode:CBC-HMAC-SHA1, Oid:2.16.840.1.101.3.4.1.4]"),
                    // 152: EVP_aes_128_cbc_hmac_sha256();
                    finding(
                            "CipherContext{ValueAction:AES-128-CBC-HMAC-SHA256}",
                            "BlockCipher:AES-128-CBC-HMAC-SHA256[BlockSize:128, KeyLength:128, "
                                    + "Mode:CBC-HMAC-SHA256, Oid:2.16.840.1.101.3.4.1]"),
                    // 153: EVP_aes_256_cbc_hmac_sha256();
                    finding(
                            "CipherContext{ValueAction:AES-256-CBC-HMAC-SHA256}",
                            "BlockCipher:AES-256-CBC-HMAC-SHA256[BlockSize:128, KeyLength:256, "
                                    + "Mode:CBC-HMAC-SHA256, Oid:2.16.840.1.101.3.4.1.4]"),
                    // 160: EVP_PKEY_CTX_set_rsa_padding(ctx, 4);
                    finding(
                            "CipherContext{ValueAction:RSA-OAEP}",
                            "PublicKeyEncryption:RSA-OAEP[Oid:1.2.840.113549.1.1.7, Padding:OAEP]"),
                    // 161: const EVP_MD* oaep_md = EVP_sha256();
                    finding(
                            "DigestContext{ValueAction:SHA-256}",
                            "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, DigestSize:256, "
                                    + "Oid:2.16.840.1.101.3.4.2.1]"),
                    // 164: EVP_PKEY_CTX_set_rsa_oaep_md_name(ctx, "SHA2-256", NULL);
                    finding(
                            "DigestContext{Algorithm:SHA-256}",
                            "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, DigestSize:256, "
                                    + "Oid:2.16.840.1.101.3.4.2.1]"),
                    // 175: EVP_ASYM_CIPHER_fetch(NULL, "RSA", NULL);
                    finding(
                            "CipherContext{Algorithm:RSA}",
                            "PublicKeyEncryption:RSA[Oid:1.2.840.113549.1.1.1]"),
                    // 176: EVP_get_cipherbyname("AES-256-GCM");
                    finding(
                            "CipherContext{Algorithm:AES-256-GCM}",
                            "AuthenticatedEncryption:AES-256-GCM[BlockSize:128, KeyLength:256, Mode:GCM, "
                                    + "Oid:2.16.840.1.101.3.4.1.46]"),
                    // 177: EVP_des_ede3_wrap();
                    finding(
                            "CipherContext{ValueAction:DES-EDE3-WRAP}",
                            "BlockCipher:DESede168-WRAP[BlockSize:64, KeyLength:168, Mode:WRAP]"),
                    // 194: EVP_aes_128_cfb();
                    finding(
                            "CipherContext{ValueAction:AES-128-CFB}",
                            "BlockCipher:AES-128-CFB[BlockSize:128, KeyLength:128, Mode:CFB, "
                                    + "Oid:2.16.840.1.101.3.4.1.4]"),
                    // 195: EVP_des_cfb();
                    finding(
                            "CipherContext{ValueAction:DES-CFB}",
                            "BlockCipher:DES-56-CFB[BlockSize:64, KeyLength:56, Mode:CFB]"),
                    // 196: EVP_des_ede3_cfb();
                    finding(
                            "CipherContext{ValueAction:DESede3-CFB64}",
                            "BlockCipher:DESede168-CFB64[BlockSize:64, KeyLength:168, Mode:CFB64]"),
                    // 197: EVP_bf_cfb();
                    finding(
                            "CipherContext{ValueAction:BLOWFISH-CFB}",
                            "BlockCipher:Blowfish-128-CFB[KeyLength:128, Mode:CFB]"),
                    // 198: EVP_aes_192_cfb();
                    finding(
                            "CipherContext{ValueAction:AES-192-CFB}",
                            "BlockCipher:AES-192-CFB[BlockSize:128, KeyLength:192, Mode:CFB, "
                                    + "Oid:2.16.840.1.101.3.4.1.24]"),
                    // 199: EVP_aes_256_cfb();
                    finding(
                            "CipherContext{ValueAction:AES-256-CFB}",
                            "BlockCipher:AES-256-CFB[BlockSize:128, KeyLength:256, Mode:CFB, "
                                    + "Oid:2.16.840.1.101.3.4.1.44]"),
                    // 200: EVP_aria_128_cfb();
                    finding(
                            "CipherContext{ValueAction:ARIA-128-CFB}",
                            "BlockCipher:ARIA-128-CFB[KeyLength:128, Mode:CFB]"),
                    // 201: EVP_aria_192_cfb();
                    finding(
                            "CipherContext{ValueAction:ARIA-192-CFB}",
                            "BlockCipher:ARIA-192-CFB[KeyLength:192, Mode:CFB]"),
                    // 202: EVP_aria_256_cfb();
                    finding(
                            "CipherContext{ValueAction:ARIA-256-CFB}",
                            "BlockCipher:ARIA-256-CFB[KeyLength:256, Mode:CFB]"),
                    // 203: EVP_camellia_128_cfb();
                    finding(
                            "CipherContext{ValueAction:CAMELLIA-128-CFB}",
                            "BlockCipher:CAMELLIA-128-CFB[KeyLength:128, Mode:CFB]"),
                    // 204: EVP_camellia_192_cfb();
                    finding(
                            "CipherContext{ValueAction:CAMELLIA-192-CFB}",
                            "BlockCipher:CAMELLIA-192-CFB[KeyLength:192, Mode:CFB]"),
                    // 205: EVP_camellia_256_cfb();
                    finding(
                            "CipherContext{ValueAction:CAMELLIA-256-CFB}",
                            "BlockCipher:CAMELLIA-256-CFB[KeyLength:256, Mode:CFB]"),
                    // 206: EVP_cast5_cfb();
                    finding(
                            "CipherContext{ValueAction:CAST5-CFB}",
                            "BlockCipher:CAST5-128-CFB[BlockSize:64, KeyLength:128, Mode:CFB]"),
                    // 207: EVP_des_ede_cfb();
                    finding(
                            "CipherContext{ValueAction:DESede-CFB64}",
                            "BlockCipher:DESede112-CFB64[BlockSize:64, KeyLength:112, Mode:CFB64]"),
                    // 208: EVP_idea_cfb();
                    finding(
                            "CipherContext{ValueAction:IDEA-CFB}",
                            "BlockCipher:IDEA-CFB[Mode:CFB]"),
                    // 209: EVP_rc2_cfb();
                    finding(
                            "CipherContext{ValueAction:RC2-CFB}",
                            "BlockCipher:RC2-128-CFB[KeyLength:128, Mode:CFB]"),
                    // 210: EVP_rc5_32_12_16_cfb();
                    finding(
                            "CipherContext{ValueAction:RC5-CFB}",
                            "BlockCipher:RC5-128-CFB[KeyLength:128, Mode:CFB]"),
                    // 211: EVP_seed_cfb();
                    finding(
                            "CipherContext{ValueAction:SEED-CFB}",
                            "BlockCipher:SEED-128-CFB[BlockSize:128, KeyLength:128, Mode:CFB]"),
                    // 212: EVP_sm4_cfb();
                    finding("CipherContext{ValueAction:SM4-CFB}", "BlockCipher:SM4-CFB[Mode:CFB]"),
                    // 216: EVP_get_cipherbynid(NID_aes_256_gcm);
                    finding(
                            "CipherContext{ValueAction:AES-256-GCM}",
                            "AuthenticatedEncryption:AES-256-GCM[BlockSize:128, KeyLength:256, Mode:GCM, "
                                    + "Oid:2.16.840.1.101.3.4.1.46]"),
                    // 217: EVP_get_cipherbynid(1018);
                    finding(
                            "CipherContext{ValueAction:CHACHA20-POLY1305}",
                            "AuthenticatedEncryption:ChaCha20-Poly1305[MessageDigest:Poly1305[Digest:DIGEST]]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/cipher/OpenSSLEvpCipherTestFile.cc", this);
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
