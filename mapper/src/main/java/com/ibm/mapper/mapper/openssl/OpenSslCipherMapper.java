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
package com.ibm.mapper.mapper.openssl;

import com.ibm.mapper.mapper.IMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.Aria;
import com.ibm.mapper.model.algorithms.Blowfish;
import com.ibm.mapper.model.algorithms.Camellia;
import com.ibm.mapper.model.algorithms.ChaCha20;
import com.ibm.mapper.model.algorithms.ChaCha20Poly1305;
import com.ibm.mapper.model.algorithms.DES;
import com.ibm.mapper.model.algorithms.DESX;
import com.ibm.mapper.model.algorithms.DESede;
import com.ibm.mapper.model.algorithms.IDEA;
import com.ibm.mapper.model.algorithms.RC2;
import com.ibm.mapper.model.algorithms.RC4;
import com.ibm.mapper.model.algorithms.RC5;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.RSAssaPSS;
import com.ibm.mapper.model.algorithms.SEED;
import com.ibm.mapper.model.algorithms.SM2;
import com.ibm.mapper.model.algorithms.SM4;
import com.ibm.mapper.model.algorithms.cast.CAST128;
import com.ibm.mapper.model.mode.CBC;
import com.ibm.mapper.model.mode.CCM;
import com.ibm.mapper.model.mode.CFB;
import com.ibm.mapper.model.mode.CTR;
import com.ibm.mapper.model.mode.ECB;
import com.ibm.mapper.model.mode.GCM;
import com.ibm.mapper.model.mode.GCMSIV;
import com.ibm.mapper.model.mode.KW;
import com.ibm.mapper.model.mode.KWP;
import com.ibm.mapper.model.mode.OCB;
import com.ibm.mapper.model.mode.OFB;
import com.ibm.mapper.model.mode.SIV;
import com.ibm.mapper.model.mode.XTS;
import com.ibm.mapper.model.padding.OAEP;
import com.ibm.mapper.model.padding.PKCS1;
import com.ibm.mapper.model.padding.Raw;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Maps the OpenSSL cipher names (the names accepted by {@code EVP_CIPHER_fetch} and {@code
 * EVP_get_cipherbyname}, and the names the cipher detection rules give the {@code EVP_*} cipher
 * functions and the legacy cipher functions) to the model.
 */
public class OpenSslCipherMapper implements IMapper {

    @Nonnull
    @Override
    public Optional<? extends INode> parse(
            @Nullable final String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }
        final String name = str.toUpperCase().trim();
        return switch (name) {

            // AES (Advanced Encryption Standard)

            // AES-128
            case "AES-128-CBC" ->
                    Optional.of(new AES(128, new CBC(detectionLocation), detectionLocation));
            case "AES-128-ECB" ->
                    Optional.of(new AES(128, new ECB(detectionLocation), detectionLocation));
            case "AES-128-GCM" ->
                    Optional.of(new AES(128, new GCM(detectionLocation), detectionLocation));
            case "AES-128-CTR" ->
                    Optional.of(new AES(128, new CTR(detectionLocation), detectionLocation));
            case "AES-128-CCM" ->
                    Optional.of(new AES(128, new CCM(detectionLocation), detectionLocation));
            case "AES-128-CFB" ->
                    Optional.of(new AES(128, new CFB(detectionLocation), detectionLocation));
            case "AES-128-CFB1" ->
                    Optional.of(new AES(128, new CFB(1, detectionLocation), detectionLocation));
            case "AES-128-CFB8" ->
                    Optional.of(new AES(128, new CFB(8, detectionLocation), detectionLocation));
            case "AES-128-CFB128" ->
                    Optional.of(new AES(128, new CFB(128, detectionLocation), detectionLocation));
            case "AES-128-OFB" ->
                    Optional.of(new AES(128, new OFB(detectionLocation), detectionLocation));
            case "AES-128-XTS" ->
                    Optional.of(new AES(128, new XTS(detectionLocation), detectionLocation));
            case "AES-128-OCB" ->
                    Optional.of(new AES(128, new OCB(detectionLocation), detectionLocation));
            case "AES-128-WRAP" ->
                    Optional.of(new AES(128, new KW(detectionLocation), detectionLocation));
            case "AES-128-WRAP-PAD" ->
                    Optional.of(new AES(128, new KWP(detectionLocation), detectionLocation));

            // AES-192
            case "AES-192-CBC" ->
                    Optional.of(new AES(192, new CBC(detectionLocation), detectionLocation));
            case "AES-192-ECB" ->
                    Optional.of(new AES(192, new ECB(detectionLocation), detectionLocation));
            case "AES-192-GCM" ->
                    Optional.of(new AES(192, new GCM(detectionLocation), detectionLocation));
            case "AES-192-CFB" ->
                    Optional.of(new AES(192, new CFB(detectionLocation), detectionLocation));
            case "AES-192-CFB1" ->
                    Optional.of(new AES(192, new CFB(1, detectionLocation), detectionLocation));
            case "AES-192-CFB8" ->
                    Optional.of(new AES(192, new CFB(8, detectionLocation), detectionLocation));
            case "AES-192-CFB128" ->
                    Optional.of(new AES(192, new CFB(128, detectionLocation), detectionLocation));
            case "AES-192-OFB" ->
                    Optional.of(new AES(192, new OFB(detectionLocation), detectionLocation));
            case "AES-192-OCB" ->
                    Optional.of(new AES(192, new OCB(detectionLocation), detectionLocation));
            case "AES-192-WRAP" ->
                    Optional.of(new AES(192, new KW(detectionLocation), detectionLocation));
            case "AES-192-WRAP-PAD" ->
                    Optional.of(new AES(192, new KWP(detectionLocation), detectionLocation));
            case "AES-192-CTR" ->
                    Optional.of(new AES(192, new CTR(detectionLocation), detectionLocation));
            case "AES-192-CCM" ->
                    Optional.of(new AES(192, new CCM(detectionLocation), detectionLocation));

            // AES-256
            case "AES-256-CBC" ->
                    Optional.of(new AES(256, new CBC(detectionLocation), detectionLocation));
            case "AES-256-ECB" ->
                    Optional.of(new AES(256, new ECB(detectionLocation), detectionLocation));
            case "AES-256-GCM" ->
                    Optional.of(new AES(256, new GCM(detectionLocation), detectionLocation));
            case "AES-256-CTR" ->
                    Optional.of(new AES(256, new CTR(detectionLocation), detectionLocation));
            case "AES-256-CCM" ->
                    Optional.of(new AES(256, new CCM(detectionLocation), detectionLocation));
            case "AES-256-CFB" ->
                    Optional.of(new AES(256, new CFB(detectionLocation), detectionLocation));
            case "AES-256-CFB1" ->
                    Optional.of(new AES(256, new CFB(1, detectionLocation), detectionLocation));
            case "AES-256-CFB8" ->
                    Optional.of(new AES(256, new CFB(8, detectionLocation), detectionLocation));
            case "AES-256-CFB128" ->
                    Optional.of(new AES(256, new CFB(128, detectionLocation), detectionLocation));
            case "AES-256-OFB" ->
                    Optional.of(new AES(256, new OFB(detectionLocation), detectionLocation));
            case "AES-256-XTS" ->
                    Optional.of(new AES(256, new XTS(detectionLocation), detectionLocation));
            case "AES-256-OCB" ->
                    Optional.of(new AES(256, new OCB(detectionLocation), detectionLocation));
            case "AES-256-WRAP" ->
                    Optional.of(new AES(256, new KW(detectionLocation), detectionLocation));
            case "AES-256-WRAP-PAD" ->
                    Optional.of(new AES(256, new KWP(detectionLocation), detectionLocation));

            // Provider-only AES modes (no EVP_* convenience functions)
            case "AES-128-SIV" ->
                    Optional.of(new AES(128, new SIV(detectionLocation), detectionLocation));
            case "AES-192-SIV" ->
                    Optional.of(new AES(192, new SIV(detectionLocation), detectionLocation));
            case "AES-256-SIV" ->
                    Optional.of(new AES(256, new SIV(detectionLocation), detectionLocation));
            case "AES-128-GCM-SIV" ->
                    Optional.of(new AES(128, new GCMSIV(detectionLocation), detectionLocation));
            case "AES-192-GCM-SIV" ->
                    Optional.of(new AES(192, new GCMSIV(detectionLocation), detectionLocation));
            case "AES-256-GCM-SIV" ->
                    Optional.of(new AES(256, new GCMSIV(detectionLocation), detectionLocation));
            case "AES-128-CBC-CTS" ->
                    Optional.of(
                            new AES(
                                    128,
                                    new Mode("CBC-CTS", detectionLocation),
                                    detectionLocation));
            case "AES-192-CBC-CTS" ->
                    Optional.of(
                            new AES(
                                    192,
                                    new Mode("CBC-CTS", detectionLocation),
                                    detectionLocation));
            case "AES-256-CBC-CTS" ->
                    Optional.of(
                            new AES(
                                    256,
                                    new Mode("CBC-CTS", detectionLocation),
                                    detectionLocation));
            case "AES-128-WRAP-INV" ->
                    Optional.of(
                            new AES(
                                    128,
                                    new Mode("WRAP-INV", detectionLocation),
                                    detectionLocation));
            case "AES-192-WRAP-INV" ->
                    Optional.of(
                            new AES(
                                    192,
                                    new Mode("WRAP-INV", detectionLocation),
                                    detectionLocation));
            case "AES-256-WRAP-INV" ->
                    Optional.of(
                            new AES(
                                    256,
                                    new Mode("WRAP-INV", detectionLocation),
                                    detectionLocation));
            case "AES-128-WRAP-PAD-INV" ->
                    Optional.of(
                            new AES(
                                    128,
                                    new Mode("WRAP-PAD-INV", detectionLocation),
                                    detectionLocation));
            case "AES-192-WRAP-PAD-INV" ->
                    Optional.of(
                            new AES(
                                    192,
                                    new Mode("WRAP-PAD-INV", detectionLocation),
                                    detectionLocation));
            case "AES-256-WRAP-PAD-INV" ->
                    Optional.of(
                            new AES(
                                    256,
                                    new Mode("WRAP-PAD-INV", detectionLocation),
                                    detectionLocation));
            case "AES-128-CBC-HMAC-SHA1" ->
                    Optional.of(
                            new AES(
                                    128,
                                    new Mode("CBC-HMAC-SHA1", detectionLocation),
                                    detectionLocation));
            case "AES-128-CBC-HMAC-SHA256" ->
                    Optional.of(
                            new AES(
                                    128,
                                    new Mode("CBC-HMAC-SHA256", detectionLocation),
                                    detectionLocation));
            case "AES-192-CBC-HMAC-SHA1" ->
                    Optional.of(
                            new AES(
                                    192,
                                    new Mode("CBC-HMAC-SHA1", detectionLocation),
                                    detectionLocation));
            case "AES-192-CBC-HMAC-SHA256" ->
                    Optional.of(
                            new AES(
                                    192,
                                    new Mode("CBC-HMAC-SHA256", detectionLocation),
                                    detectionLocation));
            case "AES-256-CBC-HMAC-SHA1" ->
                    Optional.of(
                            new AES(
                                    256,
                                    new Mode("CBC-HMAC-SHA1", detectionLocation),
                                    detectionLocation));
            case "AES-256-CBC-HMAC-SHA256" ->
                    Optional.of(
                            new AES(
                                    256,
                                    new Mode("CBC-HMAC-SHA256", detectionLocation),
                                    detectionLocation));

            // Provider-only AES ETM (Encrypt-then-MAC) modes
            case "AES-128-CBC-HMAC-SHA1-ETM" ->
                    Optional.of(
                            new AES(
                                    128,
                                    new Mode("CBC-HMAC-SHA1-ETM", detectionLocation),
                                    detectionLocation));
            case "AES-192-CBC-HMAC-SHA1-ETM" ->
                    Optional.of(
                            new AES(
                                    192,
                                    new Mode("CBC-HMAC-SHA1-ETM", detectionLocation),
                                    detectionLocation));
            case "AES-256-CBC-HMAC-SHA1-ETM" ->
                    Optional.of(
                            new AES(
                                    256,
                                    new Mode("CBC-HMAC-SHA1-ETM", detectionLocation),
                                    detectionLocation));
            case "AES-128-CBC-HMAC-SHA256-ETM" ->
                    Optional.of(
                            new AES(
                                    128,
                                    new Mode("CBC-HMAC-SHA256-ETM", detectionLocation),
                                    detectionLocation));
            case "AES-192-CBC-HMAC-SHA256-ETM" ->
                    Optional.of(
                            new AES(
                                    192,
                                    new Mode("CBC-HMAC-SHA256-ETM", detectionLocation),
                                    detectionLocation));
            case "AES-256-CBC-HMAC-SHA256-ETM" ->
                    Optional.of(
                            new AES(
                                    256,
                                    new Mode("CBC-HMAC-SHA256-ETM", detectionLocation),
                                    detectionLocation));
            case "AES-128-CBC-HMAC-SHA512-ETM" ->
                    Optional.of(
                            new AES(
                                    128,
                                    new Mode("CBC-HMAC-SHA512-ETM", detectionLocation),
                                    detectionLocation));
            case "AES-192-CBC-HMAC-SHA512-ETM" ->
                    Optional.of(
                            new AES(
                                    192,
                                    new Mode("CBC-HMAC-SHA512-ETM", detectionLocation),
                                    detectionLocation));
            case "AES-256-CBC-HMAC-SHA512-ETM" ->
                    Optional.of(
                            new AES(
                                    256,
                                    new Mode("CBC-HMAC-SHA512-ETM", detectionLocation),
                                    detectionLocation));

            // Camellia

            // Camellia-128
            case "CAMELLIA-128-ECB" ->
                    Optional.of(new Camellia(128, new ECB(detectionLocation), detectionLocation));
            case "CAMELLIA-128-CBC" ->
                    Optional.of(new Camellia(128, new CBC(detectionLocation), detectionLocation));
            case "CAMELLIA-128-CFB" ->
                    Optional.of(new Camellia(128, new CFB(detectionLocation), detectionLocation));
            case "CAMELLIA-128-CFB1" ->
                    Optional.of(
                            new Camellia(128, new CFB(1, detectionLocation), detectionLocation));
            case "CAMELLIA-128-CFB8" ->
                    Optional.of(
                            new Camellia(128, new CFB(8, detectionLocation), detectionLocation));
            case "CAMELLIA-128-CFB128" ->
                    Optional.of(
                            new Camellia(128, new CFB(128, detectionLocation), detectionLocation));
            case "CAMELLIA-128-OFB" ->
                    Optional.of(new Camellia(128, new OFB(detectionLocation), detectionLocation));
            case "CAMELLIA-128-CTR" ->
                    Optional.of(new Camellia(128, new CTR(detectionLocation), detectionLocation));
            case "CAMELLIA-128-GCM" ->
                    Optional.of(new Camellia(128, new GCM(detectionLocation), detectionLocation));
            case "CAMELLIA-128-CCM" ->
                    Optional.of(new Camellia(128, new CCM(detectionLocation), detectionLocation));

            // Camellia-192
            case "CAMELLIA-192-ECB" ->
                    Optional.of(new Camellia(192, new ECB(detectionLocation), detectionLocation));
            case "CAMELLIA-192-CBC" ->
                    Optional.of(new Camellia(192, new CBC(detectionLocation), detectionLocation));
            case "CAMELLIA-192-CFB" ->
                    Optional.of(new Camellia(192, new CFB(detectionLocation), detectionLocation));
            case "CAMELLIA-192-CFB1" ->
                    Optional.of(
                            new Camellia(192, new CFB(1, detectionLocation), detectionLocation));
            case "CAMELLIA-192-CFB8" ->
                    Optional.of(
                            new Camellia(192, new CFB(8, detectionLocation), detectionLocation));
            case "CAMELLIA-192-CFB128" ->
                    Optional.of(
                            new Camellia(192, new CFB(128, detectionLocation), detectionLocation));
            case "CAMELLIA-192-OFB" ->
                    Optional.of(new Camellia(192, new OFB(detectionLocation), detectionLocation));
            case "CAMELLIA-192-CTR" ->
                    Optional.of(new Camellia(192, new CTR(detectionLocation), detectionLocation));
            case "CAMELLIA-192-GCM" ->
                    Optional.of(new Camellia(192, new GCM(detectionLocation), detectionLocation));
            case "CAMELLIA-192-CCM" ->
                    Optional.of(new Camellia(192, new CCM(detectionLocation), detectionLocation));

            // Camellia-256
            case "CAMELLIA-256-ECB" ->
                    Optional.of(new Camellia(256, new ECB(detectionLocation), detectionLocation));
            case "CAMELLIA-256-CBC" ->
                    Optional.of(new Camellia(256, new CBC(detectionLocation), detectionLocation));
            case "CAMELLIA-256-CFB" ->
                    Optional.of(new Camellia(256, new CFB(detectionLocation), detectionLocation));
            case "CAMELLIA-256-CFB1" ->
                    Optional.of(
                            new Camellia(256, new CFB(1, detectionLocation), detectionLocation));
            case "CAMELLIA-256-CFB8" ->
                    Optional.of(
                            new Camellia(256, new CFB(8, detectionLocation), detectionLocation));
            case "CAMELLIA-256-CFB128" ->
                    Optional.of(
                            new Camellia(256, new CFB(128, detectionLocation), detectionLocation));
            case "CAMELLIA-256-OFB" ->
                    Optional.of(new Camellia(256, new OFB(detectionLocation), detectionLocation));
            case "CAMELLIA-256-CTR" ->
                    Optional.of(new Camellia(256, new CTR(detectionLocation), detectionLocation));
            case "CAMELLIA-256-GCM" ->
                    Optional.of(new Camellia(256, new GCM(detectionLocation), detectionLocation));
            case "CAMELLIA-256-CCM" ->
                    Optional.of(new Camellia(256, new CCM(detectionLocation), detectionLocation));

            // Provider-only Camellia modes
            case "CAMELLIA-128-CBC-CTS" ->
                    Optional.of(
                            new Camellia(
                                    128,
                                    new Mode("CBC-CTS", detectionLocation),
                                    detectionLocation));
            case "CAMELLIA-192-CBC-CTS" ->
                    Optional.of(
                            new Camellia(
                                    192,
                                    new Mode("CBC-CTS", detectionLocation),
                                    detectionLocation));
            case "CAMELLIA-256-CBC-CTS" ->
                    Optional.of(
                            new Camellia(
                                    256,
                                    new Mode("CBC-CTS", detectionLocation),
                                    detectionLocation));

            // ARIA

            // ARIA-128
            case "ARIA-128-ECB" ->
                    Optional.of(new Aria(128, new ECB(detectionLocation), detectionLocation));
            case "ARIA-128-CBC" ->
                    Optional.of(new Aria(128, new CBC(detectionLocation), detectionLocation));
            case "ARIA-128-CFB" ->
                    Optional.of(new Aria(128, new CFB(detectionLocation), detectionLocation));
            case "ARIA-128-CFB1" ->
                    Optional.of(new Aria(128, new CFB(1, detectionLocation), detectionLocation));
            case "ARIA-128-CFB8" ->
                    Optional.of(new Aria(128, new CFB(8, detectionLocation), detectionLocation));
            case "ARIA-128-CFB128" ->
                    Optional.of(new Aria(128, new CFB(128, detectionLocation), detectionLocation));
            case "ARIA-128-OFB" ->
                    Optional.of(new Aria(128, new OFB(detectionLocation), detectionLocation));
            case "ARIA-128-CTR" ->
                    Optional.of(new Aria(128, new CTR(detectionLocation), detectionLocation));
            case "ARIA-128-GCM" ->
                    Optional.of(new Aria(128, new GCM(detectionLocation), detectionLocation));
            case "ARIA-128-CCM" ->
                    Optional.of(new Aria(128, new CCM(detectionLocation), detectionLocation));

            // ARIA-192
            case "ARIA-192-ECB" ->
                    Optional.of(new Aria(192, new ECB(detectionLocation), detectionLocation));
            case "ARIA-192-CBC" ->
                    Optional.of(new Aria(192, new CBC(detectionLocation), detectionLocation));
            case "ARIA-192-CFB" ->
                    Optional.of(new Aria(192, new CFB(detectionLocation), detectionLocation));
            case "ARIA-192-CFB1" ->
                    Optional.of(new Aria(192, new CFB(1, detectionLocation), detectionLocation));
            case "ARIA-192-CFB8" ->
                    Optional.of(new Aria(192, new CFB(8, detectionLocation), detectionLocation));
            case "ARIA-192-CFB128" ->
                    Optional.of(new Aria(192, new CFB(128, detectionLocation), detectionLocation));
            case "ARIA-192-OFB" ->
                    Optional.of(new Aria(192, new OFB(detectionLocation), detectionLocation));
            case "ARIA-192-CTR" ->
                    Optional.of(new Aria(192, new CTR(detectionLocation), detectionLocation));
            case "ARIA-192-GCM" ->
                    Optional.of(new Aria(192, new GCM(detectionLocation), detectionLocation));
            case "ARIA-192-CCM" ->
                    Optional.of(new Aria(192, new CCM(detectionLocation), detectionLocation));

            // ARIA-256
            case "ARIA-256-ECB" ->
                    Optional.of(new Aria(256, new ECB(detectionLocation), detectionLocation));
            case "ARIA-256-CBC" ->
                    Optional.of(new Aria(256, new CBC(detectionLocation), detectionLocation));
            case "ARIA-256-CFB" ->
                    Optional.of(new Aria(256, new CFB(detectionLocation), detectionLocation));
            case "ARIA-256-CFB1" ->
                    Optional.of(new Aria(256, new CFB(1, detectionLocation), detectionLocation));
            case "ARIA-256-CFB8" ->
                    Optional.of(new Aria(256, new CFB(8, detectionLocation), detectionLocation));
            case "ARIA-256-CFB128" ->
                    Optional.of(new Aria(256, new CFB(128, detectionLocation), detectionLocation));
            case "ARIA-256-OFB" ->
                    Optional.of(new Aria(256, new OFB(detectionLocation), detectionLocation));
            case "ARIA-256-CTR" ->
                    Optional.of(new Aria(256, new CTR(detectionLocation), detectionLocation));
            case "ARIA-256-GCM" ->
                    Optional.of(new Aria(256, new GCM(detectionLocation), detectionLocation));
            case "ARIA-256-CCM" ->
                    Optional.of(new Aria(256, new CCM(detectionLocation), detectionLocation));

            // SM4 (Chinese National Standard)

            case "SM4-ECB" -> Optional.of(new SM4(new ECB(detectionLocation), detectionLocation));
            case "SM4-CBC" -> Optional.of(new SM4(new CBC(detectionLocation), detectionLocation));
            case "SM4-CFB" -> Optional.of(new SM4(new CFB(detectionLocation), detectionLocation));
            case "SM4-CFB128" ->
                    Optional.of(new SM4(new CFB(128, detectionLocation), detectionLocation));
            case "SM4-OFB" -> Optional.of(new SM4(new OFB(detectionLocation), detectionLocation));
            case "SM4-CTR" -> Optional.of(new SM4(new CTR(detectionLocation), detectionLocation));
            case "SM4-GCM" -> Optional.of(new SM4(new GCM(detectionLocation), detectionLocation));
            case "SM4-CCM" -> Optional.of(new SM4(new CCM(detectionLocation), detectionLocation));
            case "SM4-XTS" -> Optional.of(new SM4(new XTS(detectionLocation), detectionLocation));

            // DES / 3DES

            case "DES-CBC" -> Optional.of(new DES(new CBC(detectionLocation), detectionLocation));
            case "DES-ECB" -> Optional.of(new DES(new ECB(detectionLocation), detectionLocation));
            case "DES-CFB" -> Optional.of(new DES(new CFB(detectionLocation), detectionLocation));
            case "DES-CFB1" ->
                    Optional.of(new DES(new CFB(1, detectionLocation), detectionLocation));
            case "DES-CFB8" ->
                    Optional.of(new DES(new CFB(8, detectionLocation), detectionLocation));
            case "DES-CFB64" ->
                    Optional.of(new DES(new CFB(64, detectionLocation), detectionLocation));
            case "DES-OFB" -> Optional.of(new DES(new OFB(detectionLocation), detectionLocation));

            // DESX (DES with pre/post XOR whitening)
            case "DESX-CBC" -> Optional.of(new DESX(new CBC(detectionLocation), detectionLocation));

            // DESede (2-key Triple-DES, 112-bit effective key strength)
            case "DESEDE" -> Optional.of(new DESede(112, detectionLocation));
            case "DESEDE-ECB" ->
                    Optional.of(new DESede(112, new ECB(detectionLocation), detectionLocation));
            case "DESEDE-CBC" ->
                    Optional.of(new DESede(112, new CBC(detectionLocation), detectionLocation));
            case "DESEDE-CFB64" ->
                    Optional.of(new DESede(112, new CFB(64, detectionLocation), detectionLocation));
            case "DESEDE-OFB" ->
                    Optional.of(new DESede(112, new OFB(detectionLocation), detectionLocation));

            // DESede3 (3-key Triple-DES, 168-bit effective key strength)
            case "DESEDE3" -> Optional.of(new DESede(168, detectionLocation));
            case "DESEDE3-ECB" ->
                    Optional.of(new DESede(168, new ECB(detectionLocation), detectionLocation));
            case "DES-EDE3-WRAP" ->
                    Optional.of(new DESede(168, new KW(detectionLocation), detectionLocation));
            case "DESEDE3-CBC" ->
                    Optional.of(new DESede(168, new CBC(detectionLocation), detectionLocation));
            case "DESEDE3-CFB1" ->
                    Optional.of(new DESede(168, new CFB(1, detectionLocation), detectionLocation));
            case "DESEDE3-CFB8" ->
                    Optional.of(new DESede(168, new CFB(8, detectionLocation), detectionLocation));
            case "DESEDE3-CFB64" ->
                    Optional.of(new DESede(168, new CFB(64, detectionLocation), detectionLocation));
            case "DESEDE3-OFB" ->
                    Optional.of(new DESede(168, new OFB(detectionLocation), detectionLocation));

            // Blowfish

            case "BLOWFISH-ECB" ->
                    Optional.of(new Blowfish(128, new ECB(detectionLocation), detectionLocation));
            case "BLOWFISH-CBC" ->
                    Optional.of(new Blowfish(128, new CBC(detectionLocation), detectionLocation));
            case "BLOWFISH-CFB" ->
                    Optional.of(new Blowfish(128, new CFB(detectionLocation), detectionLocation));
            case "BLOWFISH-CFB64" ->
                    Optional.of(
                            new Blowfish(128, new CFB(64, detectionLocation), detectionLocation));
            case "BLOWFISH-OFB" ->
                    Optional.of(new Blowfish(128, new OFB(detectionLocation), detectionLocation));

            // CAST5 (CAST-128)

            case "CAST5-ECB" ->
                    Optional.of(new CAST128(128, new ECB(detectionLocation), detectionLocation));
            case "CAST5-CBC" ->
                    Optional.of(new CAST128(128, new CBC(detectionLocation), detectionLocation));
            case "CAST5-CFB" ->
                    Optional.of(new CAST128(128, new CFB(detectionLocation), detectionLocation));
            case "CAST5-CFB64" ->
                    Optional.of(
                            new CAST128(128, new CFB(64, detectionLocation), detectionLocation));
            case "CAST5-OFB" ->
                    Optional.of(new CAST128(128, new OFB(detectionLocation), detectionLocation));

            // RC2

            case "RC2-ECB" ->
                    Optional.of(new RC2(128, new ECB(detectionLocation), detectionLocation));
            case "RC2-CBC" ->
                    Optional.of(new RC2(128, new CBC(detectionLocation), detectionLocation));
            case "RC2-CFB" ->
                    Optional.of(new RC2(128, new CFB(detectionLocation), detectionLocation));
            case "RC2-CFB64" ->
                    Optional.of(new RC2(128, new CFB(64, detectionLocation), detectionLocation));
            case "RC2-OFB" ->
                    Optional.of(new RC2(128, new OFB(detectionLocation), detectionLocation));
            case "RC2-40-CBC" ->
                    Optional.of(new RC2(40, new CBC(detectionLocation), detectionLocation));
            case "RC2-64-CBC" ->
                    Optional.of(new RC2(64, new CBC(detectionLocation), detectionLocation));

            // RC4 (Stream Cipher)

            case "RC4" -> Optional.of(new RC4(detectionLocation));
            case "RC4-40" -> Optional.of(new RC4(40, detectionLocation));
            case "RC4-HMAC-MD5" -> Optional.of(new RC4(detectionLocation));

            // RC5

            case "RC5-ECB" ->
                    Optional.of(new RC5(128, new ECB(detectionLocation), detectionLocation));
            case "RC5-CBC" ->
                    Optional.of(new RC5(128, new CBC(detectionLocation), detectionLocation));
            case "RC5-CFB" ->
                    Optional.of(new RC5(128, new CFB(detectionLocation), detectionLocation));
            case "RC5-CFB64" ->
                    Optional.of(new RC5(128, new CFB(64, detectionLocation), detectionLocation));
            case "RC5-OFB" ->
                    Optional.of(new RC5(128, new OFB(detectionLocation), detectionLocation));

            // IDEA

            case "IDEA-ECB" -> Optional.of(new IDEA(new ECB(detectionLocation), detectionLocation));
            case "IDEA-CBC" -> Optional.of(new IDEA(new CBC(detectionLocation), detectionLocation));
            case "IDEA-CFB" -> Optional.of(new IDEA(new CFB(detectionLocation), detectionLocation));
            case "IDEA-CFB64" ->
                    Optional.of(new IDEA(new CFB(64, detectionLocation), detectionLocation));
            case "IDEA-OFB" -> Optional.of(new IDEA(new OFB(detectionLocation), detectionLocation));

            // SEED (Korean National Standard)

            case "SEED-ECB" -> Optional.of(new SEED(new ECB(detectionLocation), detectionLocation));
            case "SEED-CBC" -> Optional.of(new SEED(new CBC(detectionLocation), detectionLocation));
            case "SEED-CFB" -> Optional.of(new SEED(new CFB(detectionLocation), detectionLocation));
            case "SEED-CFB128" ->
                    Optional.of(new SEED(new CFB(128, detectionLocation), detectionLocation));
            case "SEED-OFB" -> Optional.of(new SEED(new OFB(detectionLocation), detectionLocation));

            // Legacy AES functions (AES_set_encrypt_key, AES_cbc_encrypt, ...): the key size is
            // set by the key setup call
            case "AES" -> Optional.of(new AES(detectionLocation));
            case "AES-ECB",
                    "AES-CBC",
                    "AES-CFB1",
                    "AES-CFB8",
                    "AES-CFB128",
                    "AES-OFB",
                    "AES-IGE",
                    "AES-BI-IGE" ->
                    Optional.of(
                            new AES(mode(name.substring(4), detectionLocation), detectionLocation));
            // AES_wrap_key / AES_unwrap_key: the AES key wrap of RFC 3394
            case "AES-WRAP" -> Optional.of(new AES(new KW(detectionLocation), detectionLocation));

            // Legacy three-key Triple DES functions (DES_ede3_cbc_encrypt, ...)
            case "3DES-CBC", "3DES-ECB", "3DES-CFB", "3DES-OFB" ->
                    Optional.of(
                            new DESede(
                                    168,
                                    new Mode(name.substring(5), detectionLocation),
                                    detectionLocation));
            // DES_xcbc_encrypt is DESX in CBC mode, as EVP_desx_cbc
            case "DES-XCBC" -> Optional.of(new DESX(new CBC(detectionLocation), detectionLocation));

            // Legacy (pre-EVP) key setup: the cipher is known, its mode is not
            case "DES" -> Optional.of(new DES(detectionLocation));
            case "BLOWFISH" -> Optional.of(new Blowfish(detectionLocation));
            case "CAST5" -> Optional.of(new CAST128(detectionLocation));
            case "IDEA" -> Optional.of(new IDEA(detectionLocation));
            case "RC2" -> Optional.of(new RC2(detectionLocation));
            case "RC5" -> Optional.of(new RC5(detectionLocation));
            case "SEED" -> Optional.of(new SEED(detectionLocation));
            case "CAMELLIA" -> Optional.of(new Camellia(detectionLocation));

            // Legacy Camellia functions: the key size is set by Camellia_set_key
            case "CAMELLIA-CBC" -> Optional.of(camellia("CBC", detectionLocation));
            case "CAMELLIA-CFB1" -> Optional.of(camellia("CFB1", detectionLocation));
            case "CAMELLIA-CFB8" -> Optional.of(camellia("CFB8", detectionLocation));
            case "CAMELLIA-CFB128" -> Optional.of(camellia("CFB128", detectionLocation));
            case "CAMELLIA-CTR" -> Optional.of(camellia("CTR", detectionLocation));
            case "CAMELLIA-ECB" -> Optional.of(camellia("ECB", detectionLocation));
            case "CAMELLIA-OFB" -> Optional.of(camellia("OFB", detectionLocation));

            // Legacy RSA encryption and its paddings
            case "RSA-ENCRYPT", "RSA-DECRYPT" -> Optional.of(new RSA(detectionLocation));
            case "RSA-NO-PADDING" -> {
                final RSA rsa = new RSA(detectionLocation);
                rsa.put(new Raw(detectionLocation));
                yield Optional.of(rsa);
            }
            case "RSA-OAEP", "RSA-OAEP-MGF1" ->
                    Optional.of(rsaWithPadding(new OAEP(detectionLocation), detectionLocation));
            case "RSA-PKCS1-TYPE2" ->
                    Optional.of(rsaWithPadding(new PKCS1(detectionLocation), detectionLocation));
            // PKCS#1 type 1 and X9.31 paddings are used for RSA signatures
            case "RSA-PKCS1" -> Optional.of(OpenSslRsaSignatureSchemes.pkcs1v15(detectionLocation));
            case "RSA-X931" -> Optional.of(OpenSslRsaSignatureSchemes.x931(detectionLocation));
            // RSA_PKCS1_PSS_PADDING selects RSA-PSS signatures
            case "RSA-PSS" -> Optional.of(new RSAssaPSS(detectionLocation));

            // ChaCha20

            case "CHACHA20" -> Optional.of(new ChaCha20(detectionLocation));
            case "CHACHA20-POLY1305" -> Optional.of(new ChaCha20Poly1305(detectionLocation));

            // SM2 Public Key Encryption

            // Asymmetric ciphers fetched by EVP_ASYM_CIPHER_fetch
            case "RSA" -> Optional.of(new RSA(detectionLocation));
            case "SM2", "SM2-PKE" ->
                    Optional.of(new SM2(PublicKeyEncryption.class, new SM2(detectionLocation)));

            default -> Optional.empty();
        };
    }

    /**
     * Maps the label of a legacy (pre-EVP) cipher function, e.g. {@code BLOWFISH-CBC} for {@code
     * BF_cbc_encrypt}. The label names the cipher and its mode but not the key length, which the
     * key setup function of the key sets ({@code BF_set_key}). Unlike the {@code EVP_*} function of
     * the same name ({@code EVP_bf_cbc}), whose key length is 128 bits by default, a cipher with a
     * variable key length gets no key length from the label.
     */
    @Nonnull
    public Optional<? extends INode> parseLegacy(
            @Nullable final String str, @Nonnull DetectionLocation detectionLocation) {
        return parse(str, detectionLocation)
                .map(
                        cipher -> {
                            if (cipher instanceof Blowfish
                                    || cipher instanceof CAST128
                                    || cipher instanceof RC2
                                    || cipher instanceof RC5) {
                                cipher.removeChildOfType(KeyLength.class);
                            }
                            return cipher;
                        });
    }

    @Nonnull
    private static Camellia camellia(
            @Nonnull String mode, @Nonnull DetectionLocation detectionLocation) {
        Camellia camellia = new Camellia(detectionLocation);
        camellia.put(mode(mode, detectionLocation));
        return camellia;
    }

    /**
     * The mode of operation with the given OpenSSL name, e.g. {@code CFB8}. A mode the model has a
     * class for is built from that class, which gives it its CBOM mode and its OID.
     */
    @Nonnull
    private static Mode mode(@Nonnull String name, @Nonnull DetectionLocation detectionLocation) {
        return switch (name) {
            case "CBC" -> new CBC(detectionLocation);
            case "CCM" -> new CCM(detectionLocation);
            case "CTR" -> new CTR(detectionLocation);
            case "ECB" -> new ECB(detectionLocation);
            case "GCM" -> new GCM(detectionLocation);
            case "OFB" -> new OFB(detectionLocation);
            case "CFB" -> new CFB(detectionLocation);
            default ->
                    name.startsWith("CFB")
                            ? new CFB(Integer.parseInt(name.substring(3)), detectionLocation)
                            : new Mode(name, detectionLocation);
        };
    }

    @Nonnull
    private static RSA rsaWithPadding(
            @Nonnull INode padding, @Nonnull DetectionLocation detectionLocation) {
        RSA rsa = new RSA(detectionLocation);
        rsa.put(padding);
        return rsa;
    }
}
