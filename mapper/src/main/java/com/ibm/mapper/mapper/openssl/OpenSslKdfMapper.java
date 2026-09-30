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
import com.ibm.mapper.model.Cipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.ANSIX942;
import com.ibm.mapper.model.algorithms.ANSIX963;
import com.ibm.mapper.model.algorithms.Argon2;
import com.ibm.mapper.model.algorithms.ConcatenationKDF;
import com.ibm.mapper.model.algorithms.DES;
import com.ibm.mapper.model.algorithms.DESede;
import com.ibm.mapper.model.algorithms.HKDF;
import com.ibm.mapper.model.algorithms.HMAC;
import com.ibm.mapper.model.algorithms.HMACDRBGKDF;
import com.ibm.mapper.model.algorithms.KDFCounter;
import com.ibm.mapper.model.algorithms.KRB5KDF;
import com.ibm.mapper.model.algorithms.MD2;
import com.ibm.mapper.model.algorithms.MD5;
import com.ibm.mapper.model.algorithms.PBES1;
import com.ibm.mapper.model.algorithms.PBES2;
import com.ibm.mapper.model.algorithms.PBKDF1;
import com.ibm.mapper.model.algorithms.PBKDF2;
import com.ibm.mapper.model.algorithms.PKCS12KDF;
import com.ibm.mapper.model.algorithms.PKCS12PBE;
import com.ibm.mapper.model.algorithms.PVKKDF;
import com.ibm.mapper.model.algorithms.RC2;
import com.ibm.mapper.model.algorithms.RC4;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.SSHKDF;
import com.ibm.mapper.model.algorithms.Scrypt;
import com.ibm.mapper.model.algorithms.TLSPRF;
import com.ibm.mapper.model.mode.CBC;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Maps the OpenSSL key derivation names (the names accepted by {@code EVP_KDF_fetch}, the KDF key
 * types of {@code EVP_PKEY_CTX_new_id}, and the names the KDF and password-based encryption
 * detection rules give the PKCS#5 and PKCS#12 functions) to the model.
 */
public class OpenSslKdfMapper implements IMapper {

    @Nonnull
    @Override
    public Optional<? extends INode> parse(
            @Nullable final String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }
        return switch (str.toUpperCase().trim()) {
            // Names accepted by EVP_KDF_fetch. The digest of a KDF is set through the
            // "digest" OSSL_PARAM of its context and is attached to the node as a child.
            case "PBKDF2", "1.2.840.113549.1.5.12" -> Optional.of(new PBKDF2(detectionLocation));
            case "PBKDF1" -> Optional.of(new PBKDF1(detectionLocation));
            case "HKDF" -> Optional.of(new HKDF(detectionLocation));
            case "HKDF-SHA256" -> Optional.of(new HKDF(new SHA2(256, detectionLocation)));
            case "HKDF-SHA384" -> Optional.of(new HKDF(new SHA2(384, detectionLocation)));
            case "HKDF-SHA512" -> Optional.of(new HKDF(new SHA2(512, detectionLocation)));
            // the TLS 1.3 key schedule is built on HKDF (RFC 8446, section 7.1)
            case "TLS13-KDF" -> Optional.of(new HKDF(detectionLocation));
            case "TLS1-PRF" -> Optional.of(new TLSPRF(detectionLocation));
            case "SSKDF" -> Optional.of(new ConcatenationKDF(detectionLocation));
            case "X963KDF", "X963-KDF" -> Optional.of(new ANSIX963(detectionLocation));
            case "X942KDF-ASN1", "X942KDF" -> Optional.of(new ANSIX942("ASN1", detectionLocation));
            case "X942KDF-CONCAT" -> Optional.of(new ANSIX942("CONCAT", detectionLocation));
            // SP 800-108 KBKDF runs in counter mode unless the "mode" parameter selects
            // feedback mode
            case "KBKDF" -> Optional.of(new KDFCounter(detectionLocation));
            case "SSHKDF" -> Optional.of(new SSHKDF(detectionLocation));
            case "SCRYPT", "ID-SCRYPT", "1.3.6.1.4.1.11591.4.11" ->
                    Optional.of(new Scrypt(detectionLocation));
            case "KRB5KDF" -> Optional.of(new KRB5KDF(detectionLocation));
            case "ARGON2D" -> Optional.of(new Argon2(Argon2.Variant.D, detectionLocation));
            case "ARGON2I" -> Optional.of(new Argon2(Argon2.Variant.I, detectionLocation));
            case "ARGON2ID" -> Optional.of(new Argon2(Argon2.Variant.ID, detectionLocation));
            case "PKCS12KDF" -> Optional.of(new PKCS12KDF(detectionLocation));
            case "PVKKDF" -> Optional.of(new PVKKDF(detectionLocation));
            case "HMAC-DRBG-KDF" -> Optional.of(new HMACDRBGKDF(detectionLocation));

            // PKCS12_PBE_keyivgen and PKCS5_PBE_keyivgen: the cipher and the digest come from
            // their arguments
            case "PKCS12-PBE" -> Optional.of(new PKCS12PBE(detectionLocation));
            case "PBES1" -> Optional.of(new PBES1(detectionLocation));
            // PKCS8_encrypt and EVP_PBE_CipherInit: PBES2 with the cipher given with it
            case "PBES2" -> Optional.of(new PBES2(detectionLocation));

            // PKCS#5 v1.5 schemes (PBES1), selected by their NID
            case "PBE-MD2-DES" ->
                    Optional.of(pbes1(new MD2(detectionLocation), des(detectionLocation)));
            case "PBE-MD5-DES" ->
                    Optional.of(pbes1(new MD5(detectionLocation), des(detectionLocation)));
            case "PBE-SHA1-DES" ->
                    Optional.of(pbes1(new SHA(detectionLocation), des(detectionLocation)));
            case "PBE-MD2-RC2-64" ->
                    Optional.of(pbes1(new MD2(detectionLocation), rc2(detectionLocation)));
            case "PBE-MD5-RC2-64" ->
                    Optional.of(pbes1(new MD5(detectionLocation), rc2(detectionLocation)));
            case "PBE-SHA1-RC2-64" ->
                    Optional.of(pbes1(new SHA(detectionLocation), rc2(detectionLocation)));

            // Encryption selected by the key and certificate NIDs of PKCS12_create
            case "PBE-SHA1-RC4-128" ->
                    Optional.of(
                            new PKCS12PBE(
                                    new SHA(detectionLocation), new RC4(128, detectionLocation)));
            case "PBE-SHA1-RC4-40" ->
                    Optional.of(
                            new PKCS12PBE(
                                    new SHA(detectionLocation), new RC4(40, detectionLocation)));
            case "PBE-SHA1-3DES" ->
                    Optional.of(
                            new PKCS12PBE(
                                    new SHA(detectionLocation),
                                    new DESede(
                                            168, new CBC(detectionLocation), detectionLocation)));
            case "PBE-SHA1-2DES" ->
                    Optional.of(
                            new PKCS12PBE(
                                    new SHA(detectionLocation),
                                    new DESede(
                                            112, new CBC(detectionLocation), detectionLocation)));
            case "PBE-SHA1-RC2-128" ->
                    Optional.of(
                            new PKCS12PBE(
                                    new SHA(detectionLocation),
                                    new RC2(128, new CBC(detectionLocation), detectionLocation)));
            case "PBE-SHA1-RC2-40" ->
                    Optional.of(
                            new PKCS12PBE(
                                    new SHA(detectionLocation),
                                    new RC2(40, new CBC(detectionLocation), detectionLocation)));
            // PBES2 with PBKDF2 and HMAC-SHA256, the default of PKCS12_create
            case "PBES2-AES-128-CBC" -> Optional.of(pbes2WithAesCbc(128, detectionLocation));
            case "PBES2-AES-192-CBC" -> Optional.of(pbes2WithAesCbc(192, detectionLocation));
            case "PBES2-AES-256-CBC" -> Optional.of(pbes2WithAesCbc(256, detectionLocation));
            case "PBES2-DES-EDE3-CBC" ->
                    Optional.of(
                            new PBES2(
                                    new HMAC(new SHA2(256, detectionLocation)),
                                    new DESede(
                                            168, new CBC(detectionLocation), detectionLocation)));

            // an ECDH or DH derivation whose KDF type is set to none uses no KDF
            case "NONE" -> Optional.empty();

            // PKCS5_PBKDF2_HMAC: the digest comes from its md argument
            case "PBKDF2-HMAC" -> Optional.of(new PBKDF2(detectionLocation));
            case "PBKDF2-HMAC-SHA1" -> Optional.of(new PBKDF2(new SHA(detectionLocation)));

            default -> Optional.empty();
        };
    }

    @Nonnull
    private static PBES1 pbes1(@Nonnull MessageDigest digest, @Nonnull Cipher cipher) {
        return new PBES1(digest, cipher);
    }

    /** The DES-CBC of the PKCS#5 v1.5 schemes. */
    @Nonnull
    private static DES des(@Nonnull DetectionLocation detectionLocation) {
        return new DES(56, new CBC(detectionLocation), detectionLocation);
    }

    /** The 64-bit RC2-CBC of the PKCS#5 v1.5 schemes. */
    @Nonnull
    private static RC2 rc2(@Nonnull DetectionLocation detectionLocation) {
        return new RC2(64, new CBC(detectionLocation), detectionLocation);
    }

    @Nonnull
    private static PBES2 pbes2WithAesCbc(
            int keyLength, @Nonnull DetectionLocation detectionLocation) {
        return new PBES2(
                new HMAC(new SHA2(256, detectionLocation)),
                new AES(keyLength, new CBC(detectionLocation), detectionLocation));
    }
}
