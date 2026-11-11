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
package com.ibm.output.cyclondx.builder;

import com.ibm.mapper.model.AlgorithmFamily;
import com.ibm.mapper.model.EllipticCurve;
import java.util.EnumMap;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Translates mapper model values to identifiers of the CycloneDX 1.7 cryptography registry
 * (cryptography-defs.schema.json). Only registry identifiers are returned, so an invalid value can
 * never be emitted for the {@code algorithmFamily} and {@code ellipticCurve} enumerations.
 */
public final class CycloneDxRegistry {
    private static final Map<AlgorithmFamily, String> FAMILIES =
            new EnumMap<>(AlgorithmFamily.class);
    private static final Map<String, String> CURVES =
            Map.ofEntries(
                    Map.entry("secp192r1", "nist/P-192"),
                    Map.entry("secp224r1", "nist/P-224"),
                    Map.entry("secp256r1", "nist/P-256"),
                    Map.entry("secp384r1", "nist/P-384"),
                    Map.entry("secp521r1", "nist/P-521"),
                    Map.entry("secp256k1", "secg/secp256k1"),
                    Map.entry("sect163k1", "secg/sect163k1"),
                    Map.entry("sect163r2", "secg/sect163r2"),
                    Map.entry("sect233k1", "secg/sect233k1"),
                    Map.entry("sect233r1", "secg/sect233r1"),
                    Map.entry("sect283k1", "secg/sect283k1"),
                    Map.entry("sect283r1", "secg/sect283r1"),
                    Map.entry("sect409k1", "secg/sect409k1"),
                    Map.entry("sect409r1", "secg/sect409r1"),
                    Map.entry("sect571k1", "secg/sect571k1"),
                    Map.entry("sect571r1", "secg/sect571r1"),
                    Map.entry("Brainpoolp256r1", "brainpool/brainpoolP256r1"),
                    Map.entry("Brainpoolp384r1", "brainpool/brainpoolP384r1"),
                    Map.entry("Brainpoolp512r1", "brainpool/brainpoolP512r1"),
                    Map.entry("Curve25519", "other/Curve25519"),
                    Map.entry("Curve448", "other/Curve448"),
                    Map.entry("Edwards25519", "other/Ed25519"),
                    Map.entry("Edwards448", "other/Ed448"));

    static {
        FAMILIES.put(AlgorithmFamily.AES, "AES");
        FAMILIES.put(AlgorithmFamily.ARIA, "ARIA");
        FAMILIES.put(AlgorithmFamily.BLAKE2, "BLAKE2");
        FAMILIES.put(AlgorithmFamily.BLAKE3, "BLAKE3");
        FAMILIES.put(AlgorithmFamily.BLOWFISH, "Blowfish");
        FAMILIES.put(AlgorithmFamily.CAMELLIA, "CAMELLIA");
        FAMILIES.put(AlgorithmFamily.CAST5, "CAST5");
        FAMILIES.put(AlgorithmFamily.CAST6, "CAST6");
        FAMILIES.put(AlgorithmFamily.CHACHA20, "ChaCha20");
        FAMILIES.put(AlgorithmFamily.CMAC, "CMAC");
        FAMILIES.put(AlgorithmFamily.DES, "DES");
        FAMILIES.put(AlgorithmFamily.DSA, "DSA");
        FAMILIES.put(AlgorithmFamily.ECDH, "ECDH");
        FAMILIES.put(AlgorithmFamily.ECDSA, "ECDSA");
        FAMILIES.put(AlgorithmFamily.ECIES, "ECIES");
        FAMILIES.put(AlgorithmFamily.EDDSA, "EdDSA");
        FAMILIES.put(AlgorithmFamily.ELGAMAL, "ElGamal");
        FAMILIES.put(AlgorithmFamily.FFDH, "FFDH");
        FAMILIES.put(AlgorithmFamily.HC, "HC");
        FAMILIES.put(AlgorithmFamily.HKDF, "HKDF");
        FAMILIES.put(AlgorithmFamily.HMAC, "HMAC");
        FAMILIES.put(AlgorithmFamily.IDEA, "IDEA");
        FAMILIES.put(AlgorithmFamily.LMS, "LMS");
        FAMILIES.put(AlgorithmFamily.MD2, "MD2");
        FAMILIES.put(AlgorithmFamily.MD4, "MD4");
        FAMILIES.put(AlgorithmFamily.MD5, "MD5");
        FAMILIES.put(AlgorithmFamily.ML_DSA, "ML-DSA");
        FAMILIES.put(AlgorithmFamily.ML_KEM, "ML-KEM");
        FAMILIES.put(AlgorithmFamily.MQV, "MQV");
        FAMILIES.put(AlgorithmFamily.PBES1, "PBES1");
        FAMILIES.put(AlgorithmFamily.PBES2, "PBES2");
        FAMILIES.put(AlgorithmFamily.PBKDF1, "PBKDF1");
        FAMILIES.put(AlgorithmFamily.PBKDF2, "PBKDF2");
        FAMILIES.put(AlgorithmFamily.POLY1305, "Poly1305");
        FAMILIES.put(AlgorithmFamily.RC2, "RC2");
        FAMILIES.put(AlgorithmFamily.RC4, "RC4");
        FAMILIES.put(AlgorithmFamily.RC5, "RC5");
        FAMILIES.put(AlgorithmFamily.RC6, "RC6");
        FAMILIES.put(AlgorithmFamily.RIPEMD, "RIPEMD");
        FAMILIES.put(AlgorithmFamily.RSAES_OAEP, "RSAES-OAEP");
        FAMILIES.put(AlgorithmFamily.RSAES_PKCS1, "RSAES-PKCS1");
        FAMILIES.put(AlgorithmFamily.RSASSA_PKCS1, "RSASSA-PKCS1");
        FAMILIES.put(AlgorithmFamily.RSASSA_PSS, "RSASSA-PSS");
        FAMILIES.put(AlgorithmFamily.SALSA20, "Salsa20");
        FAMILIES.put(AlgorithmFamily.SCRYPT, "scrypt");
        FAMILIES.put(AlgorithmFamily.SEED, "SEED");
        FAMILIES.put(AlgorithmFamily.SERPENT, "Serpent");
        FAMILIES.put(AlgorithmFamily.SHA1, "SHA-1");
        FAMILIES.put(AlgorithmFamily.SHA2, "SHA-2");
        FAMILIES.put(AlgorithmFamily.SHA3, "SHA-3");
        FAMILIES.put(AlgorithmFamily.SIPHASH, "SipHash");
        FAMILIES.put(AlgorithmFamily.SKIPJACK, "Skipjack");
        FAMILIES.put(AlgorithmFamily.SLH_DSA, "SLH-DSA");
        FAMILIES.put(AlgorithmFamily.SM2, "SM2");
        FAMILIES.put(AlgorithmFamily.SM3, "SM3");
        FAMILIES.put(AlgorithmFamily.SM4, "SM4");
        FAMILIES.put(AlgorithmFamily.SP800_108, "SP800-108");
        FAMILIES.put(AlgorithmFamily.SRP, "SRP");
        FAMILIES.put(AlgorithmFamily.TRIPLE_DES, "3DES");
        FAMILIES.put(AlgorithmFamily.TWOFISH, "Twofish");
        FAMILIES.put(AlgorithmFamily.WHIRLPOOL, "Whirlpool");
        FAMILIES.put(AlgorithmFamily.XMSS, "XMSS");
        FAMILIES.put(AlgorithmFamily.ZUC, "ZUC");
    }

    private CycloneDxRegistry() {}

    @Nonnull
    public static Optional<String> algorithmFamily(@Nonnull AlgorithmFamily family) {
        return Optional.ofNullable(FAMILIES.get(family));
    }

    @Nonnull
    public static Optional<String> ellipticCurve(@Nonnull EllipticCurve curve) {
        return Optional.ofNullable(CURVES.get(curve.asString()));
    }
}
