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
package com.ibm.plugin.rules.detection.openssl.digest;

import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.factory.IValueFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Resolves an OpenSSL bare-name string argument (e.g. a digest {@code md_name} like {@code
 * "SHA256"}, or an EC group name like {@code "P-256"}) to the identifier string the corresponding
 * {@code Cxx*ContextTranslator} switches on, using a caller-supplied canonicalization table. Names
 * already in a recognized form, or not recognized at all, pass through unchanged, so the
 * translator's own {@code default -> Optional.empty()} decides whether they surface.
 */
public final class OpenSSLNameCanonicalizerFactory implements IValueFactory<AstNode> {

    /**
     * {@code md_name} argument (e.g. {@code EVP_PKEY_CTX_set_rsa_mgf1_md_name}) → {@code
     * "SHA-256"}.
     */
    public static final Map<String, String> DIGEST_NAMES =
            Map.ofEntries(
                    Map.entry("SHA1", "SHA-1"),
                    Map.entry("SHA224", "SHA-224"),
                    Map.entry("SHA256", "SHA-256"),
                    Map.entry("SHA384", "SHA-384"),
                    Map.entry("SHA512", "SHA-512"),
                    Map.entry("SHA512-224", "SHA-512/224"),
                    Map.entry("SHA512-256", "SHA-512/256"),
                    // OpenSSL 3.x provider fetch names (OSSL_DIGEST_NAME_*)
                    Map.entry("SHA2-224", "SHA-224"),
                    Map.entry("SHA2-256", "SHA-256"),
                    Map.entry("SHA2-384", "SHA-384"),
                    Map.entry("SHA2-512", "SHA-512"),
                    Map.entry("SHA2-512/224", "SHA-512/224"),
                    Map.entry("SHA2-512/256", "SHA-512/256"),
                    // SHAKE (extendable-output functions)
                    Map.entry("SHAKE128", "SHAKE128"),
                    Map.entry("SHAKE256", "SHAKE256"),
                    // RIPEMD-160 (OpenSSL's short_name is "RMD160", the long/EVP name is
                    // "RIPEMD160")
                    Map.entry("RIPEMD160", "RIPEMD160"),
                    Map.entry("RMD160", "RIPEMD160"),
                    // BLAKE2 (OpenSSL's EVP_MD names have no hyphen; the translator's canonical
                    // form does)
                    Map.entry("BLAKE2B512", "BLAKE2B-512"),
                    Map.entry("BLAKE2S256", "BLAKE2S-256"),
                    // MDC-2 (ISO/IEC 10118-2, built on DES)
                    Map.entry("MDC2", "MDC2"),
                    // SSLv3 MAC digest names (OBJ_sn_ssl3_sha1 / OBJ_sn_ssl3_md5): the same
                    // SHA-1/MD5 algorithms, just under their SSLv3 cipher-suite object name
                    Map.entry("SSL3-SHA1", "SHA-1"),
                    Map.entry("SSL3-MD5", "MD5"),
                    // OpenSSL 3.x name macros (core_names.h), e.g. OSSL_DIGEST_NAME_SHA2_256
                    Map.entry("OSSL_DIGEST_NAME_MD5", "MD5"),
                    Map.entry("OSSL_DIGEST_NAME_MD5_SHA1", "MD5-SHA1"),
                    Map.entry("OSSL_DIGEST_NAME_SHA1", "SHA-1"),
                    Map.entry("OSSL_DIGEST_NAME_SHA2_224", "SHA-224"),
                    Map.entry("OSSL_DIGEST_NAME_SHA2_256", "SHA-256"),
                    Map.entry("OSSL_DIGEST_NAME_SHA2_384", "SHA-384"),
                    Map.entry("OSSL_DIGEST_NAME_SHA2_512", "SHA-512"),
                    Map.entry("OSSL_DIGEST_NAME_SHA2_512_224", "SHA-512/224"),
                    Map.entry("OSSL_DIGEST_NAME_SHA2_512_256", "SHA-512/256"),
                    Map.entry("OSSL_DIGEST_NAME_MD2", "MD2"),
                    Map.entry("OSSL_DIGEST_NAME_MD4", "MD4"),
                    Map.entry("OSSL_DIGEST_NAME_MDC2", "MDC2"),
                    Map.entry("OSSL_DIGEST_NAME_RIPEMD160", "RIPEMD160"),
                    Map.entry("OSSL_DIGEST_NAME_SHA3_224", "SHA3-224"),
                    Map.entry("OSSL_DIGEST_NAME_SHA3_256", "SHA3-256"),
                    Map.entry("OSSL_DIGEST_NAME_SHA3_384", "SHA3-384"),
                    Map.entry("OSSL_DIGEST_NAME_SHA3_512", "SHA3-512"),
                    Map.entry("OSSL_DIGEST_NAME_SM3", "SM3"),
                    // short-name macros (obj_mac.h), e.g. SN_sha256
                    Map.entry("SN_MD5", "MD5"),
                    Map.entry("SN_SHA1", "SHA-1"),
                    Map.entry("SN_SHA224", "SHA-224"),
                    Map.entry("SN_SHA256", "SHA-256"),
                    Map.entry("SN_SHA384", "SHA-384"),
                    Map.entry("SN_SHA512", "SHA-512"),
                    Map.entry("SN_SHA3_224", "SHA3-224"),
                    Map.entry("SN_SHA3_256", "SHA3-256"),
                    Map.entry("SN_SHA3_384", "SHA3-384"),
                    Map.entry("SN_SHA3_512", "SHA3-512"),
                    Map.entry("SN_SM3", "SM3"),
                    Map.entry("SN_RIPEMD160", "RIPEMD160"));

    /** Curve/group name argument (e.g. {@code EVP_PKEY_CTX_set_group_name}) → {@code "EC-P256"}. */
    public static final Map<String, String> GROUP_NAMES =
            Map.ofEntries(
                    Map.entry("P-192", "EC-P192"),
                    Map.entry("PRIME192V1", "EC-P192"),
                    Map.entry("P-224", "EC-P224"),
                    Map.entry("SECP224R1", "EC-P224"),
                    Map.entry("P-256", "EC-P256"),
                    Map.entry("PRIME256V1", "EC-P256"),
                    Map.entry("SECP256R1", "EC-P256"),
                    Map.entry("P-384", "EC-P384"),
                    Map.entry("SECP384R1", "EC-P384"),
                    Map.entry("P-521", "EC-P521"),
                    Map.entry("SECP521R1", "EC-P521"),
                    Map.entry("SECP256K1", "EC-SECP256K1"),
                    Map.entry("BRAINPOOLP256R1", "EC-BRAINPOOLP256R1"),
                    Map.entry("BRAINPOOLP384R1", "EC-BRAINPOOLP384R1"),
                    Map.entry("BRAINPOOLP512R1", "EC-BRAINPOOLP512R1"));

    /**
     * Cipher name or alias accepted by {@code EVP_CIPHER_fetch}/{@code EVP_get_cipherbyname} (e.g.
     * {@code "DES3"}) → the name the cipher translator maps (e.g. {@code "DESede3-CBC"}). Names
     * that already are in that form, such as {@code "AES-256-GCM"}, are not listed.
     */
    public static final Map<String, String> CIPHER_NAMES =
            Map.ofEntries(
                    // AES: size-only aliases select CBC; "id-aes*" names are the ASN.1 names
                    Map.entry("AES128", "AES-128-CBC"),
                    Map.entry("AES128-WRAP", "AES-128-WRAP"),
                    Map.entry("AES128-WRAP-INV", "AES-128-WRAP-INV"),
                    Map.entry("AES128-WRAP-PAD", "AES-128-WRAP-PAD"),
                    Map.entry("AES128-WRAP-PAD-INV", "AES-128-WRAP-PAD-INV"),
                    Map.entry("ID-AES128-CCM", "AES-128-CCM"),
                    Map.entry("ID-AES128-GCM", "AES-128-GCM"),
                    Map.entry("ID-AES128-WRAP", "AES-128-WRAP"),
                    Map.entry("ID-AES128-WRAP-PAD", "AES-128-WRAP-PAD"),
                    Map.entry("AES192", "AES-192-CBC"),
                    Map.entry("AES192-WRAP", "AES-192-WRAP"),
                    Map.entry("AES192-WRAP-INV", "AES-192-WRAP-INV"),
                    Map.entry("AES192-WRAP-PAD", "AES-192-WRAP-PAD"),
                    Map.entry("AES192-WRAP-PAD-INV", "AES-192-WRAP-PAD-INV"),
                    Map.entry("ID-AES192-CCM", "AES-192-CCM"),
                    Map.entry("ID-AES192-GCM", "AES-192-GCM"),
                    Map.entry("ID-AES192-WRAP", "AES-192-WRAP"),
                    Map.entry("ID-AES192-WRAP-PAD", "AES-192-WRAP-PAD"),
                    Map.entry("AES256", "AES-256-CBC"),
                    Map.entry("AES256-WRAP", "AES-256-WRAP"),
                    Map.entry("AES256-WRAP-INV", "AES-256-WRAP-INV"),
                    Map.entry("AES256-WRAP-PAD", "AES-256-WRAP-PAD"),
                    Map.entry("AES256-WRAP-PAD-INV", "AES-256-WRAP-PAD-INV"),
                    Map.entry("ID-AES256-CCM", "AES-256-CCM"),
                    Map.entry("ID-AES256-GCM", "AES-256-GCM"),
                    Map.entry("ID-AES256-WRAP", "AES-256-WRAP"),
                    Map.entry("ID-AES256-WRAP-PAD", "AES-256-WRAP-PAD"),
                    // ARIA and Camellia: size-only aliases select CBC
                    Map.entry("ARIA128", "ARIA-128-CBC"),
                    Map.entry("ARIA192", "ARIA-192-CBC"),
                    Map.entry("ARIA256", "ARIA-256-CBC"),
                    Map.entry("CAMELLIA128", "CAMELLIA-128-CBC"),
                    Map.entry("CAMELLIA192", "CAMELLIA-192-CBC"),
                    Map.entry("CAMELLIA256", "CAMELLIA-256-CBC"),
                    // Blowfish
                    Map.entry("BF", "BLOWFISH-CBC"),
                    Map.entry("BLOWFISH", "BLOWFISH-CBC"),
                    Map.entry("BF-CBC", "BLOWFISH-CBC"),
                    Map.entry("BF-ECB", "BLOWFISH-ECB"),
                    Map.entry("BF-CFB", "BLOWFISH-CFB"),
                    Map.entry("BF-OFB", "BLOWFISH-OFB"),
                    // CAST5
                    Map.entry("CAST", "CAST5-CBC"),
                    Map.entry("CAST-CBC", "CAST5-CBC"),
                    // DES, two-key (DES-EDE) and three-key (DES-EDE3) Triple DES; CFB is CFB64
                    Map.entry("DES", "DES-CBC"),
                    Map.entry("DESX", "DESX-CBC"),
                    Map.entry("DES-EDE", "DESede"),
                    Map.entry("DES-EDE-ECB", "DESede-ECB"),
                    Map.entry("DES-EDE-CBC", "DESede-CBC"),
                    Map.entry("DES-EDE-CFB", "DESede-CFB64"),
                    Map.entry("DES-EDE-OFB", "DESede-OFB"),
                    Map.entry("DES-EDE3", "DESede3"),
                    Map.entry("DES-EDE3-ECB", "DESede3-ECB"),
                    Map.entry("DES-EDE3-CBC", "DESede3-CBC"),
                    Map.entry("DES3", "DESede3-CBC"),
                    Map.entry("DES-EDE3-CFB", "DESede3-CFB64"),
                    Map.entry("DES-EDE3-CFB1", "DESede3-CFB1"),
                    Map.entry("DES-EDE3-CFB8", "DESede3-CFB8"),
                    Map.entry("DES-EDE3-OFB", "DESede3-OFB"),
                    Map.entry("DES3-WRAP", "DES-EDE3-WRAP"),
                    Map.entry("ID-SMIME-ALG-CMS3DESWRAP", "DES-EDE3-WRAP"),
                    // IDEA, RC2, RC5, SEED, SM4: bare names select CBC
                    Map.entry("IDEA", "IDEA-CBC"),
                    Map.entry("RC2", "RC2-CBC"),
                    Map.entry("RC2-128", "RC2-CBC"),
                    Map.entry("RC2-40", "RC2-40-CBC"),
                    Map.entry("RC2-64", "RC2-64-CBC"),
                    Map.entry("RC5", "RC5-CBC"),
                    Map.entry("SEED", "SEED-CBC"),
                    Map.entry("SEED-OFB128", "SEED-OFB"),
                    Map.entry("SM4", "SM4-CBC"),
                    Map.entry("SM4-OFB128", "SM4-OFB"),
                    // OpenSSL 3.x name macros (core_names.h)
                    Map.entry("OSSL_CIPHER_NAME_AES_128_GCM_SIV", "AES-128-GCM-SIV"),
                    Map.entry("OSSL_CIPHER_NAME_AES_192_GCM_SIV", "AES-192-GCM-SIV"),
                    Map.entry("OSSL_CIPHER_NAME_AES_256_GCM_SIV", "AES-256-GCM-SIV"));

    /**
     * Key type name accepted by {@code EVP_PKEY_CTX_new_from_name}, {@code EVP_PKEY_Q_keygen} and
     * {@code EVP_KEYMGMT_fetch} (e.g. {@code "RSA"}, {@code "ML-KEM-768"}) → the key type name.
     */
    public static final Map<String, String> KEY_TYPE_NAMES =
            Map.ofEntries(
                    Map.entry("RSA", "RSA"),
                    Map.entry("RSA-PSS", "RSA-PSS"),
                    Map.entry("DSA", "DSA"),
                    Map.entry("DH", "DH"),
                    Map.entry("EC", "EC"),
                    Map.entry("SM2", "SM2"),
                    Map.entry("X25519", "X25519"),
                    Map.entry("X448", "X448"),
                    Map.entry("ED25519", "ED25519"),
                    Map.entry("ED448", "ED448"),
                    Map.entry("ML-KEM-512", "ML-KEM-512"),
                    Map.entry("ML-KEM-768", "ML-KEM-768"),
                    Map.entry("ML-KEM-1024", "ML-KEM-1024"),
                    Map.entry("ML-DSA-44", "ML-DSA-44"),
                    Map.entry("ML-DSA-65", "ML-DSA-65"),
                    Map.entry("ML-DSA-87", "ML-DSA-87"),
                    Map.entry("X25519MLKEM768", "X25519MLKEM768"),
                    Map.entry("X448MLKEM1024", "X448MLKEM1024"),
                    Map.entry("SECP256R1MLKEM768", "SECP256R1MLKEM768"),
                    Map.entry("SECP384R1MLKEM1024", "SECP384R1MLKEM1024"),
                    Map.entry("SLH-DSA-SHA2-128F", "SLH-DSA-SHA2-128F"),
                    Map.entry("SLH-DSA-SHA2-128S", "SLH-DSA-SHA2-128S"),
                    Map.entry("SLH-DSA-SHA2-192F", "SLH-DSA-SHA2-192F"),
                    Map.entry("SLH-DSA-SHA2-192S", "SLH-DSA-SHA2-192S"),
                    Map.entry("SLH-DSA-SHA2-256F", "SLH-DSA-SHA2-256F"),
                    Map.entry("SLH-DSA-SHA2-256S", "SLH-DSA-SHA2-256S"),
                    Map.entry("SLH-DSA-SHAKE-128F", "SLH-DSA-SHAKE-128F"),
                    Map.entry("SLH-DSA-SHAKE-128S", "SLH-DSA-SHAKE-128S"),
                    Map.entry("SLH-DSA-SHAKE-192F", "SLH-DSA-SHAKE-192F"),
                    Map.entry("SLH-DSA-SHAKE-192S", "SLH-DSA-SHAKE-192S"),
                    Map.entry("SLH-DSA-SHAKE-256F", "SLH-DSA-SHAKE-256F"),
                    Map.entry("SLH-DSA-SHAKE-256S", "SLH-DSA-SHAKE-256S"),
                    // aliases
                    Map.entry("RSAENCRYPTION", "RSA"),
                    Map.entry("RSASSA-PSS", "RSA-PSS"),
                    Map.entry("DHKEYAGREEMENT", "DH"),
                    Map.entry("DHX", "DH"),
                    Map.entry("X9.42 DH", "DH"),
                    Map.entry("ID-ECPUBLICKEY", "EC"));

    /** KDF name macro (e.g. {@code OSSL_KDF_NAME_HKDF}) → the KDF name it stands for. */
    public static final Map<String, String> KDF_NAMES =
            Map.ofEntries(
                    Map.entry("OSSL_KDF_NAME_HKDF", "HKDF"),
                    Map.entry("OSSL_KDF_NAME_TLS1_3_KDF", "TLS13-KDF"),
                    Map.entry("OSSL_KDF_NAME_PBKDF1", "PBKDF1"),
                    Map.entry("OSSL_KDF_NAME_PBKDF2", "PBKDF2"),
                    Map.entry("OSSL_KDF_NAME_SCRYPT", "SCRYPT"),
                    Map.entry("OSSL_KDF_NAME_SSHKDF", "SSHKDF"),
                    Map.entry("OSSL_KDF_NAME_SSKDF", "SSKDF"),
                    Map.entry("OSSL_KDF_NAME_TLS1_PRF", "TLS1-PRF"),
                    Map.entry("OSSL_KDF_NAME_X942KDF_ASN1", "X942KDF-ASN1"),
                    Map.entry("OSSL_KDF_NAME_X942KDF_CONCAT", "X942KDF-CONCAT"),
                    Map.entry("OSSL_KDF_NAME_X963KDF", "X963KDF"),
                    Map.entry("OSSL_KDF_NAME_KBKDF", "KBKDF"),
                    Map.entry("OSSL_KDF_NAME_KRB5KDF", "KRB5KDF"),
                    Map.entry("OSSL_KDF_NAME_HMACDRBGKDF", "HMAC-DRBG-KDF"));

    /**
     * Names of the KDFs available through the EVP_PKEY interface, and the KDF name macros that
     * stand for them → KDF names.
     */
    public static final Map<String, String> PKEY_KDF_NAMES =
            Map.ofEntries(
                    Map.entry("HKDF", "HKDF"),
                    Map.entry("TLS1-PRF", "TLS1-PRF"),
                    Map.entry("SCRYPT", "SCRYPT"),
                    Map.entry("ID-SCRYPT", "SCRYPT"),
                    Map.entry("OSSL_KDF_NAME_HKDF", "HKDF"),
                    Map.entry("OSSL_KDF_NAME_TLS1_PRF", "TLS1-PRF"),
                    Map.entry("OSSL_KDF_NAME_SCRYPT", "SCRYPT"));

    /** Key type names accepted by EVP_PKEY_new_raw_private_key_ex → key type names. */
    public static final Map<String, String> RAW_KEY_TYPE_NAMES =
            Map.ofEntries(
                    Map.entry("HMAC", "HMAC"),
                    Map.entry("CMAC", "CMAC"),
                    Map.entry("POLY1305", "POLY1305"),
                    Map.entry("SIPHASH", "SIPHASH"),
                    Map.entry("X25519", "X25519"),
                    Map.entry("X448", "X448"),
                    Map.entry("ED25519", "ED25519"),
                    Map.entry("ED448", "ED448"));

    /** MAC name macro (e.g. {@code OSSL_MAC_NAME_HMAC}) → the MAC name it stands for. */
    public static final Map<String, String> MAC_NAMES =
            Map.ofEntries(
                    Map.entry("OSSL_MAC_NAME_BLAKE2BMAC", "BLAKE2BMAC"),
                    Map.entry("OSSL_MAC_NAME_BLAKE2SMAC", "BLAKE2SMAC"),
                    Map.entry("OSSL_MAC_NAME_CMAC", "CMAC"),
                    Map.entry("OSSL_MAC_NAME_GMAC", "GMAC"),
                    Map.entry("OSSL_MAC_NAME_HMAC", "HMAC"),
                    Map.entry("OSSL_MAC_NAME_KMAC128", "KMAC128"),
                    Map.entry("OSSL_MAC_NAME_KMAC256", "KMAC256"),
                    Map.entry("OSSL_MAC_NAME_POLY1305", "POLY1305"),
                    Map.entry("OSSL_MAC_NAME_SIPHASH", "SIPHASH"));

    @Nonnull private final Map<String, String> table;
    private final boolean knownNamesOnly;

    public OpenSSLNameCanonicalizerFactory(@Nonnull Map<String, String> table) {
        this(table, false);
    }

    /**
     * @param knownNamesOnly true to resolve only the names listed in {@code table}, for arguments
     *     that select among several kinds of algorithms, e.g. a key type or a KDF
     */
    public OpenSSLNameCanonicalizerFactory(
            @Nonnull Map<String, String> table, boolean knownNamesOnly) {
        this.table = table;
        this.knownNamesOnly = knownNamesOnly;
    }

    @Override
    @Nonnull
    public Optional<IValue<AstNode>> apply(@Nonnull ResolvedValue<Object, AstNode> resolvedValue) {
        final Object value = resolvedValue.value();
        if (!(value instanceof String str)) {
            return Optional.empty();
        }
        if (knownNamesOnly && !table.containsKey(str.toUpperCase().trim())) {
            return Optional.empty();
        }
        return Optional.of(new Algorithm<>(canonicalize(table, str), resolvedValue.tree()));
    }

    /**
     * Normalizes {@code name} against {@code table} (uppercased, trimmed lookup). A name already in
     * a recognized form, or not recognized at all, passes through unchanged.
     */
    @Nonnull
    public static String canonicalize(@Nonnull Map<String, String> table, @Nonnull String name) {
        return table.getOrDefault(name.toUpperCase().trim(), name);
    }
}
