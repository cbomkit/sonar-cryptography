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

import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.Protocol;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.factory.IValueFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Map;
import java.util.Optional;
import java.util.function.BiFunction;
import java.util.function.IntUnaryOperator;
import java.util.regex.Pattern;
import javax.annotation.Nonnull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Resolves an OpenSSL numeric-or-bare-name argument (e.g. the curve NID of {@code
 * EC_KEY_new_by_curve_name(_ex)} / {@code EC_GROUP_new_by_curve_name(_ex)} / {@code
 * EVP_PKEY_CTX_set_ec_paramgen_curve_nid}, the DH group NID of {@code EVP_PKEY_CTX_set_dh_nid}, or
 * the protocol version of {@code SSL_(CTX_)set_min/max_proto_version}) to the identifier string the
 * corresponding {@code Cxx*ContextTranslator} switches on, using caller-supplied lookup tables.
 *
 * <p>The engine hands this factory a numeric code (e.g. {@code 415}) when the argument is a numeric
 * literal, or when it is an unscoped enum constant with an explicit {@code = constantExpression}
 * value. An unscoped enum constant with no explicit value instead resolves to its own declared name
 * (e.g. {@code "NID_X9_62_prime256v1"}), looked up in {@code byName}, as does an OpenSSL macro
 * constant that is not expanded because no include directories are configured (see {@code
 * CxxSemantic}). A code or name outside both tables resolves to nothing.
 */
public final class OpenSSLNidLookupFactory implements IValueFactory<AstNode> {

    private static final Logger LOGGER = LoggerFactory.getLogger(OpenSSLNidLookupFactory.class);

    /**
     * Curve NIDs (obj_mac.h) → {@code "EC-"} and the curve's short name, for the named curves the
     * mapper models (see {@code OpenSslCurveMapper}).
     */
    public static final Map<Integer, String> CURVE_BY_CODE =
            Map.ofEntries(
                    Map.entry(409, "EC-prime192v1"),
                    Map.entry(415, "EC-prime256v1"),
                    Map.entry(713, "EC-secp224r1"),
                    Map.entry(714, "EC-secp256k1"),
                    Map.entry(715, "EC-secp384r1"),
                    Map.entry(716, "EC-secp521r1"),
                    Map.entry(721, "EC-sect163k1"),
                    Map.entry(723, "EC-sect163r2"),
                    Map.entry(726, "EC-sect233k1"),
                    Map.entry(727, "EC-sect233r1"),
                    Map.entry(729, "EC-sect283k1"),
                    Map.entry(730, "EC-sect283r1"),
                    Map.entry(731, "EC-sect409k1"),
                    Map.entry(732, "EC-sect409r1"),
                    Map.entry(733, "EC-sect571k1"),
                    Map.entry(734, "EC-sect571r1"),
                    Map.entry(927, "EC-brainpoolP256r1"),
                    Map.entry(931, "EC-brainpoolP384r1"),
                    Map.entry(933, "EC-brainpoolP512r1"));

    /** Curve NID constant names → {@code "EC-"} and the curve's short name. */
    public static final Map<String, String> CURVE_BY_NAME =
            Map.ofEntries(
                    Map.entry("NID_X9_62_prime192v1", "EC-prime192v1"),
                    Map.entry("NID_secp224r1", "EC-secp224r1"),
                    Map.entry("NID_X9_62_prime256v1", "EC-prime256v1"),
                    Map.entry("NID_secp256k1", "EC-secp256k1"),
                    Map.entry("NID_secp384r1", "EC-secp384r1"),
                    Map.entry("NID_secp521r1", "EC-secp521r1"),
                    Map.entry("NID_brainpoolP256r1", "EC-brainpoolP256r1"),
                    Map.entry("NID_brainpoolP384r1", "EC-brainpoolP384r1"),
                    Map.entry("NID_brainpoolP512r1", "EC-brainpoolP512r1"),
                    Map.entry("NID_sect163k1", "EC-sect163k1"),
                    Map.entry("NID_sect163r2", "EC-sect163r2"),
                    Map.entry("NID_sect233k1", "EC-sect233k1"),
                    Map.entry("NID_sect233r1", "EC-sect233r1"),
                    Map.entry("NID_sect283k1", "EC-sect283k1"),
                    Map.entry("NID_sect283r1", "EC-sect283r1"),
                    Map.entry("NID_sect409k1", "EC-sect409k1"),
                    Map.entry("NID_sect409r1", "EC-sect409r1"),
                    Map.entry("NID_sect571k1", "EC-sect571k1"),
                    Map.entry("NID_sect571r1", "EC-sect571r1"));

    /**
     * OpenSSL key type identifiers of the KDFs available through the EVP_PKEY interface (evp.h /
     * obj_mac.h) → KDF names.
     */
    public static final Map<Integer, String> PKEY_KDF_BY_CODE =
            Map.ofEntries(
                    Map.entry(1036, "HKDF"), // EVP_PKEY_HKDF
                    Map.entry(1021, "TLS1-PRF"), // EVP_PKEY_TLS1_PRF
                    Map.entry(973, "SCRYPT")); // EVP_PKEY_SCRYPT

    /** OpenSSL KDF key type constant names → KDF names. */
    public static final Map<String, String> PKEY_KDF_BY_NAME =
            Map.ofEntries(
                    Map.entry("EVP_PKEY_HKDF", "HKDF"),
                    Map.entry("EVP_PKEY_TLS1_PRF", "TLS1-PRF"),
                    Map.entry("EVP_PKEY_SCRYPT", "SCRYPT"));

    /**
     * Encryption NIDs accepted by {@code PKCS12_create} for the private key and the certificates
     * (obj_mac.h) → password-based encryption scheme identifiers. A PKCS#12 PBE NID selects that
     * scheme; a cipher NID selects PBES2 with that cipher, and 0 selects the default, PBES2 with
     * AES-256-CBC. -1 (no encryption) is not listed.
     */
    public static final Map<Integer, String> PKCS12_ENCRYPTION_BY_CODE =
            Map.ofEntries(
                    Map.entry(144, "PBE-SHA1-RC4-128"),
                    Map.entry(145, "PBE-SHA1-RC4-40"),
                    Map.entry(146, "PBE-SHA1-3DES"),
                    Map.entry(147, "PBE-SHA1-2DES"),
                    Map.entry(148, "PBE-SHA1-RC2-128"),
                    Map.entry(149, "PBE-SHA1-RC2-40"),
                    Map.entry(419, "PBES2-AES-128-CBC"),
                    Map.entry(423, "PBES2-AES-192-CBC"),
                    Map.entry(427, "PBES2-AES-256-CBC"),
                    Map.entry(44, "PBES2-DES-EDE3-CBC"),
                    Map.entry(0, "PBES2-AES-256-CBC"));

    /**
     * Password-based encryption NIDs (obj_mac.h) → scheme identifiers, for the {@code pbe_nid} of
     * {@code PKCS8_encrypt} and the {@code OBJ_nid2obj} object given to {@code EVP_PBE_CipherInit}:
     * the PKCS#5 v1.5 (PBES1) and PKCS#12 schemes, and PBES2, whose cipher is given with it. -1
     * selects PBES2 in {@code PKCS8_encrypt}.
     */
    public static final Map<Integer, String> PBE_ALGORITHM_BY_CODE =
            Map.ofEntries(
                    Map.entry(9, "PBE-MD2-DES"),
                    Map.entry(10, "PBE-MD5-DES"),
                    Map.entry(168, "PBE-MD2-RC2-64"),
                    Map.entry(169, "PBE-MD5-RC2-64"),
                    Map.entry(170, "PBE-SHA1-DES"),
                    Map.entry(68, "PBE-SHA1-RC2-64"),
                    Map.entry(144, "PBE-SHA1-RC4-128"),
                    Map.entry(145, "PBE-SHA1-RC4-40"),
                    Map.entry(146, "PBE-SHA1-3DES"),
                    Map.entry(147, "PBE-SHA1-2DES"),
                    Map.entry(148, "PBE-SHA1-RC2-128"),
                    Map.entry(149, "PBE-SHA1-RC2-40"),
                    Map.entry(161, "PBES2"),
                    Map.entry(-1, "PBES2"));

    /** Password-based encryption NID constant names → scheme identifiers. */
    public static final Map<String, String> PBE_ALGORITHM_BY_NAME =
            Map.ofEntries(
                    Map.entry("NID_pbeWithMD2AndDES_CBC", "PBE-MD2-DES"),
                    Map.entry("NID_pbeWithMD5AndDES_CBC", "PBE-MD5-DES"),
                    Map.entry("NID_pbeWithMD2AndRC2_CBC", "PBE-MD2-RC2-64"),
                    Map.entry("NID_pbeWithMD5AndRC2_CBC", "PBE-MD5-RC2-64"),
                    Map.entry("NID_pbeWithSHA1AndDES_CBC", "PBE-SHA1-DES"),
                    Map.entry("NID_pbeWithSHA1AndRC2_CBC", "PBE-SHA1-RC2-64"),
                    Map.entry("NID_pbe_WithSHA1And128BitRC4", "PBE-SHA1-RC4-128"),
                    Map.entry("NID_pbe_WithSHA1And40BitRC4", "PBE-SHA1-RC4-40"),
                    Map.entry("NID_pbe_WithSHA1And3_Key_TripleDES_CBC", "PBE-SHA1-3DES"),
                    Map.entry("NID_pbe_WithSHA1And2_Key_TripleDES_CBC", "PBE-SHA1-2DES"),
                    Map.entry("NID_pbe_WithSHA1And128BitRC2_CBC", "PBE-SHA1-RC2-128"),
                    Map.entry("NID_pbe_WithSHA1And40BitRC2_CBC", "PBE-SHA1-RC2-40"),
                    Map.entry("NID_pbes2", "PBES2"));

    /** Encryption NID constant names accepted by {@code PKCS12_create} → scheme identifiers. */
    public static final Map<String, String> PKCS12_ENCRYPTION_BY_NAME =
            Map.ofEntries(
                    Map.entry("NID_pbe_WithSHA1And128BitRC4", "PBE-SHA1-RC4-128"),
                    Map.entry("NID_pbe_WithSHA1And40BitRC4", "PBE-SHA1-RC4-40"),
                    Map.entry("NID_pbe_WithSHA1And3_Key_TripleDES_CBC", "PBE-SHA1-3DES"),
                    Map.entry("NID_pbe_WithSHA1And2_Key_TripleDES_CBC", "PBE-SHA1-2DES"),
                    Map.entry("NID_pbe_WithSHA1And128BitRC2_CBC", "PBE-SHA1-RC2-128"),
                    Map.entry("NID_pbe_WithSHA1And40BitRC2_CBC", "PBE-SHA1-RC2-40"),
                    Map.entry("NID_aes_128_cbc", "PBES2-AES-128-CBC"),
                    Map.entry("NID_aes_192_cbc", "PBES2-AES-192-CBC"),
                    Map.entry("NID_aes_256_cbc", "PBES2-AES-256-CBC"),
                    Map.entry("NID_des_ede3_cbc", "PBES2-DES-EDE3-CBC"));

    /**
     * OpenSSL ECDH KDF types (EVP_PKEY_ECDH_KDF_*, ec.h) → KDF names; {@code "NONE"} when the
     * shared secret is used without a KDF.
     */
    public static final Map<Integer, String> ECDH_KDF_TYPE_BY_CODE =
            Map.of(1, "NONE", 2, "X963KDF");

    /** OpenSSL ECDH KDF type constant names → KDF names. */
    public static final Map<String, String> ECDH_KDF_TYPE_BY_NAME =
            Map.of(
                    "EVP_PKEY_ECDH_KDF_NONE", "NONE",
                    "EVP_PKEY_ECDH_KDF_X9_63", "X963KDF",
                    "EVP_PKEY_ECDH_KDF_X9_62", "X963KDF");

    /**
     * OpenSSL DH KDF types (EVP_PKEY_DH_KDF_*, dh.h) → KDF names; {@code "NONE"} when the shared
     * secret is used without a KDF.
     */
    public static final Map<Integer, String> DH_KDF_TYPE_BY_CODE =
            Map.of(1, "NONE", 2, "X942KDF-ASN1");

    /** OpenSSL DH KDF type constant names → KDF names. */
    public static final Map<String, String> DH_KDF_TYPE_BY_NAME =
            Map.of("EVP_PKEY_DH_KDF_NONE", "NONE", "EVP_PKEY_DH_KDF_X9_42", "X942KDF-ASN1");

    /** Key wrap algorithm NIDs of a CMS KEK recipient (obj_mac.h) → cipher names. */
    public static final Map<Integer, String> KEY_WRAP_BY_CODE =
            Map.ofEntries(
                    Map.entry(788, "AES-128-WRAP"),
                    Map.entry(789, "AES-192-WRAP"),
                    Map.entry(790, "AES-256-WRAP"),
                    Map.entry(897, "AES-128-WRAP-PAD"),
                    Map.entry(900, "AES-192-WRAP-PAD"),
                    Map.entry(903, "AES-256-WRAP-PAD"),
                    Map.entry(246, "DES-EDE3-WRAP"));

    /** Key wrap algorithm NID constant names → cipher names. */
    public static final Map<String, String> KEY_WRAP_BY_NAME =
            Map.ofEntries(
                    Map.entry("NID_id_aes128_wrap", "AES-128-WRAP"),
                    Map.entry("NID_id_aes192_wrap", "AES-192-WRAP"),
                    Map.entry("NID_id_aes256_wrap", "AES-256-WRAP"),
                    Map.entry("NID_id_aes128_wrap_pad", "AES-128-WRAP-PAD"),
                    Map.entry("NID_id_aes192_wrap_pad", "AES-192-WRAP-PAD"),
                    Map.entry("NID_id_aes256_wrap_pad", "AES-256-WRAP-PAD"),
                    Map.entry("NID_id_smime_alg_CMS3DESwrap", "DES-EDE3-WRAP"));

    /** Digest NIDs (obj_mac.h) → digest names. */
    public static final Map<Integer, String> DIGEST_BY_CODE =
            Map.ofEntries(
                    Map.entry(4, "MD5"),
                    Map.entry(64, "SHA-1"),
                    Map.entry(95, "MDC2"),
                    Map.entry(117, "RIPEMD160"),
                    Map.entry(257, "MD4"),
                    Map.entry(672, "SHA-256"),
                    Map.entry(673, "SHA-384"),
                    Map.entry(674, "SHA-512"),
                    Map.entry(675, "SHA-224"),
                    Map.entry(1056, "BLAKE2B-512"),
                    Map.entry(1057, "BLAKE2S-256"),
                    Map.entry(1094, "SHA-512/224"),
                    Map.entry(1095, "SHA-512/256"),
                    Map.entry(1096, "SHA3-224"),
                    Map.entry(1097, "SHA3-256"),
                    Map.entry(1098, "SHA3-384"),
                    Map.entry(1099, "SHA3-512"),
                    Map.entry(1100, "SHAKE128"),
                    Map.entry(1101, "SHAKE256"),
                    Map.entry(1143, "SM3"));

    /** Digest NID constant names → digest names. */
    public static final Map<String, String> DIGEST_BY_NAME =
            Map.ofEntries(
                    Map.entry("NID_md4", "MD4"),
                    Map.entry("NID_md5", "MD5"),
                    Map.entry("NID_sha1", "SHA-1"),
                    Map.entry("NID_sha224", "SHA-224"),
                    Map.entry("NID_sha256", "SHA-256"),
                    Map.entry("NID_sha384", "SHA-384"),
                    Map.entry("NID_sha512", "SHA-512"),
                    Map.entry("NID_sha512_224", "SHA-512/224"),
                    Map.entry("NID_sha512_256", "SHA-512/256"),
                    Map.entry("NID_sha3_224", "SHA3-224"),
                    Map.entry("NID_sha3_256", "SHA3-256"),
                    Map.entry("NID_sha3_384", "SHA3-384"),
                    Map.entry("NID_sha3_512", "SHA3-512"),
                    Map.entry("NID_shake128", "SHAKE128"),
                    Map.entry("NID_shake256", "SHAKE256"),
                    Map.entry("NID_ripemd160", "RIPEMD160"),
                    Map.entry("NID_sm3", "SM3"),
                    Map.entry("NID_mdc2", "MDC2"),
                    Map.entry("NID_blake2b512", "BLAKE2B-512"),
                    Map.entry("NID_blake2s256", "BLAKE2S-256"));

    /** Cipher NIDs (obj_mac.h) → cipher names. */
    public static final Map<Integer, String> CIPHER_BY_CODE =
            Map.ofEntries(
                    Map.entry(5, "RC4"),
                    Map.entry(29, "DES-ECB"),
                    Map.entry(31, "DES-CBC"),
                    Map.entry(33, "DESede3-ECB"),
                    Map.entry(44, "DESede3-CBC"),
                    Map.entry(91, "BLOWFISH-CBC"),
                    Map.entry(418, "AES-128-ECB"),
                    Map.entry(419, "AES-128-CBC"),
                    Map.entry(420, "AES-128-OFB"),
                    Map.entry(421, "AES-128-CFB"),
                    Map.entry(422, "AES-192-ECB"),
                    Map.entry(423, "AES-192-CBC"),
                    Map.entry(426, "AES-256-ECB"),
                    Map.entry(427, "AES-256-CBC"),
                    Map.entry(428, "AES-256-OFB"),
                    Map.entry(429, "AES-256-CFB"),
                    Map.entry(751, "CAMELLIA-128-CBC"),
                    Map.entry(753, "CAMELLIA-256-CBC"),
                    Map.entry(895, "AES-128-GCM"),
                    Map.entry(896, "AES-128-CCM"),
                    Map.entry(898, "AES-192-GCM"),
                    Map.entry(901, "AES-256-GCM"),
                    Map.entry(902, "AES-256-CCM"),
                    Map.entry(904, "AES-128-CTR"),
                    Map.entry(906, "AES-256-CTR"),
                    Map.entry(1018, "CHACHA20-POLY1305"),
                    Map.entry(1019, "CHACHA20"),
                    Map.entry(1134, "SM4-CBC"));

    /** Cipher NID constant names → cipher names. */
    public static final Map<String, String> CIPHER_BY_NAME =
            Map.ofEntries(
                    Map.entry("NID_aes_128_ecb", "AES-128-ECB"),
                    Map.entry("NID_aes_128_cbc", "AES-128-CBC"),
                    Map.entry("NID_aes_128_ofb128", "AES-128-OFB"),
                    Map.entry("NID_aes_128_cfb128", "AES-128-CFB"),
                    Map.entry("NID_aes_128_ctr", "AES-128-CTR"),
                    Map.entry("NID_aes_128_gcm", "AES-128-GCM"),
                    Map.entry("NID_aes_128_ccm", "AES-128-CCM"),
                    Map.entry("NID_aes_192_ecb", "AES-192-ECB"),
                    Map.entry("NID_aes_192_cbc", "AES-192-CBC"),
                    Map.entry("NID_aes_192_gcm", "AES-192-GCM"),
                    Map.entry("NID_aes_256_ecb", "AES-256-ECB"),
                    Map.entry("NID_aes_256_cbc", "AES-256-CBC"),
                    Map.entry("NID_aes_256_ofb128", "AES-256-OFB"),
                    Map.entry("NID_aes_256_cfb128", "AES-256-CFB"),
                    Map.entry("NID_aes_256_ctr", "AES-256-CTR"),
                    Map.entry("NID_aes_256_gcm", "AES-256-GCM"),
                    Map.entry("NID_aes_256_ccm", "AES-256-CCM"),
                    Map.entry("NID_chacha20", "CHACHA20"),
                    Map.entry("NID_chacha20_poly1305", "CHACHA20-POLY1305"),
                    Map.entry("NID_des_ecb", "DES-ECB"),
                    Map.entry("NID_des_cbc", "DES-CBC"),
                    Map.entry("NID_des_ede3_ecb", "DESede3-ECB"),
                    Map.entry("NID_des_ede3_cbc", "DESede3-CBC"),
                    Map.entry("NID_camellia_128_cbc", "CAMELLIA-128-CBC"),
                    Map.entry("NID_camellia_256_cbc", "CAMELLIA-256-CBC"),
                    Map.entry("NID_sm4_cbc", "SM4-CBC"),
                    Map.entry("NID_bf_cbc", "BLOWFISH-CBC"),
                    Map.entry("NID_rc4", "RC4"));

    /** HMAC NIDs (obj_mac.h) → MAC names. */
    public static final Map<Integer, String> HMAC_BY_CODE =
            Map.ofEntries(
                    Map.entry(780, "HMAC-MD5"),
                    Map.entry(781, "HMAC-SHA1"),
                    Map.entry(163, "HMAC-SHA1"),
                    Map.entry(798, "HMAC-SHA224"),
                    Map.entry(799, "HMAC-SHA256"),
                    Map.entry(800, "HMAC-SHA384"),
                    Map.entry(801, "HMAC-SHA512"));

    /** HMAC NID constant names → MAC names. */
    public static final Map<String, String> HMAC_BY_NAME =
            Map.ofEntries(
                    Map.entry("NID_hmac_md5", "HMAC-MD5"),
                    Map.entry("NID_hmac_sha1", "HMAC-SHA1"),
                    Map.entry("NID_hmacWithSHA1", "HMAC-SHA1"),
                    Map.entry("NID_hmacWithSHA224", "HMAC-SHA224"),
                    Map.entry("NID_hmacWithSHA256", "HMAC-SHA256"),
                    Map.entry("NID_hmacWithSHA384", "HMAC-SHA384"),
                    Map.entry("NID_hmacWithSHA512", "HMAC-SHA512"));

    /**
     * RSA paddings accepted by RSA_public_encrypt and RSA_private_decrypt (rsa.h) → the RSA
     * encryption scheme they select.
     */
    public static final Map<Integer, String> RSA_ENCRYPTION_PADDING_BY_CODE =
            Map.ofEntries(
                    Map.entry(1, "RSA-PKCS1-TYPE2"), // RSA_PKCS1_PADDING
                    Map.entry(3, "RSA-NO-PADDING"), // RSA_NO_PADDING
                    Map.entry(4, "RSA-OAEP"), // RSA_PKCS1_OAEP_PADDING
                    Map.entry(7, "RSA-PKCS1-TYPE2"), // RSA_PKCS1_WITH_TLS_PADDING
                    Map.entry(8, "RSA-PKCS1-TYPE2")); // RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING

    /** RSA encryption padding constant names → the RSA encryption scheme they select. */
    public static final Map<String, String> RSA_ENCRYPTION_PADDING_BY_NAME =
            Map.ofEntries(
                    Map.entry("RSA_PKCS1_PADDING", "RSA-PKCS1-TYPE2"),
                    Map.entry("RSA_NO_PADDING", "RSA-NO-PADDING"),
                    Map.entry("RSA_PKCS1_OAEP_PADDING", "RSA-OAEP"),
                    Map.entry("RSA_PKCS1_WITH_TLS_PADDING", "RSA-PKCS1-TYPE2"),
                    Map.entry("RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING", "RSA-PKCS1-TYPE2"));

    /**
     * RSA paddings accepted by RSA_private_encrypt and RSA_public_decrypt (rsa.h) → the RSA
     * signature scheme they select.
     */
    public static final Map<Integer, String> RSA_SIGNATURE_PADDING_BY_CODE =
            Map.ofEntries(
                    Map.entry(1, "RSA-PKCS1"), // RSA_PKCS1_PADDING
                    Map.entry(3, "RSA-NO-PADDING"), // RSA_NO_PADDING
                    Map.entry(5, "RSA-X931")); // RSA_X931_PADDING

    /** RSA signature padding constant names → the RSA signature scheme they select. */
    public static final Map<String, String> RSA_SIGNATURE_PADDING_BY_NAME =
            Map.ofEntries(
                    Map.entry("RSA_PKCS1_PADDING", "RSA-PKCS1"),
                    Map.entry("RSA_NO_PADDING", "RSA-NO-PADDING"),
                    Map.entry("RSA_X931_PADDING", "RSA-X931"));

    /**
     * Key types a key can be created for from raw bytes (EVP_PKEY_new_raw_private_key,
     * EVP_PKEY_new_mac_key; evp.h / obj_mac.h) → key type names.
     */
    public static final Map<Integer, String> RAW_KEY_TYPE_BY_CODE =
            Map.ofEntries(
                    Map.entry(855, "HMAC"), // EVP_PKEY_HMAC
                    Map.entry(894, "CMAC"), // EVP_PKEY_CMAC
                    Map.entry(1061, "POLY1305"), // EVP_PKEY_POLY1305
                    Map.entry(1062, "SIPHASH"), // EVP_PKEY_SIPHASH
                    Map.entry(1034, "X25519"), // EVP_PKEY_X25519
                    Map.entry(1035, "X448"), // EVP_PKEY_X448
                    Map.entry(1087, "ED25519"), // EVP_PKEY_ED25519
                    Map.entry(1088, "ED448")); // EVP_PKEY_ED448

    /** Raw key type constant names → key type names. */
    public static final Map<String, String> RAW_KEY_TYPE_BY_NAME =
            Map.ofEntries(
                    Map.entry("EVP_PKEY_HMAC", "HMAC"),
                    Map.entry("EVP_PKEY_CMAC", "CMAC"),
                    Map.entry("EVP_PKEY_POLY1305", "POLY1305"),
                    Map.entry("EVP_PKEY_SIPHASH", "SIPHASH"),
                    Map.entry("EVP_PKEY_X25519", "X25519"),
                    Map.entry("EVP_PKEY_X448", "X448"),
                    Map.entry("EVP_PKEY_ED25519", "ED25519"),
                    Map.entry("EVP_PKEY_ED448", "ED448"));

    /** OpenSSL key type identifiers (EVP_PKEY_*, evp.h / obj_mac.h) → key type names. */
    public static final Map<Integer, String> PKEY_TYPE_BY_CODE =
            Map.ofEntries(
                    Map.entry(6, "RSA"), // EVP_PKEY_RSA
                    Map.entry(912, "RSA-PSS"), // EVP_PKEY_RSA_PSS
                    Map.entry(116, "DSA"), // EVP_PKEY_DSA
                    Map.entry(28, "DH"), // EVP_PKEY_DH
                    Map.entry(920, "DH"), // EVP_PKEY_DHX
                    Map.entry(408, "EC"), // EVP_PKEY_EC
                    Map.entry(1172, "SM2"), // EVP_PKEY_SM2
                    Map.entry(1034, "X25519"), // EVP_PKEY_X25519
                    Map.entry(1035, "X448"), // EVP_PKEY_X448
                    Map.entry(1087, "ED25519"), // EVP_PKEY_ED25519
                    Map.entry(1088, "ED448")); // EVP_PKEY_ED448

    /** OpenSSL key type macro names → key type names. */
    public static final Map<String, String> PKEY_TYPE_BY_NAME =
            Map.ofEntries(
                    Map.entry("EVP_PKEY_RSA", "RSA"),
                    Map.entry("EVP_PKEY_RSA_PSS", "RSA-PSS"),
                    Map.entry("EVP_PKEY_DSA", "DSA"),
                    Map.entry("EVP_PKEY_DH", "DH"),
                    Map.entry("EVP_PKEY_DHX", "DH"),
                    Map.entry("EVP_PKEY_EC", "EC"),
                    Map.entry("EVP_PKEY_SM2", "SM2"),
                    Map.entry("EVP_PKEY_X25519", "X25519"),
                    Map.entry("EVP_PKEY_X448", "X448"),
                    Map.entry("EVP_PKEY_ED25519", "ED25519"),
                    Map.entry("EVP_PKEY_ED448", "ED448"));

    /** OpenSSL named DH group NID codes (obj_mac.h) → key-length identifier strings. */
    public static final Map<Integer, String> DH_GROUP_BY_CODE =
            Map.ofEntries(
                    Map.entry(1126, "DH-2048"), // NID_ffdhe2048
                    Map.entry(1127, "DH-3072"), // NID_ffdhe3072
                    Map.entry(1128, "DH-4096")); // NID_ffdhe4096

    /** OpenSSL named DH group NID constant names → key-length identifier strings. */
    public static final Map<String, String> DH_GROUP_BY_NAME =
            Map.ofEntries(
                    Map.entry("NID_ffdhe2048", "DH-2048"),
                    Map.entry("NID_ffdhe3072", "DH-3072"),
                    Map.entry("NID_ffdhe4096", "DH-4096"));

    /** Numeric OpenSSL protocol version codes → version strings. */
    public static final Map<Integer, String> PROTO_VERSION_BY_CODE =
            Map.ofEntries(
                    Map.entry(0x0300, "SSLv3.0"),
                    Map.entry(0x0301, "TLSv1.0"),
                    Map.entry(0x0302, "TLSv1.1"),
                    Map.entry(0x0303, "TLSv1.2"),
                    Map.entry(0x0304, "TLSv1.3"),
                    Map.entry(0xFEFF, "DTLSv1.0"),
                    Map.entry(0xFEFD, "DTLSv1.2"),
                    Map.entry(0x0100, "DTLSv1.0")); // DTLS1_BAD_VER

    /**
     * OpenSSL version constant names → version strings, used when an unscoped enum constant with no
     * explicit value resolves to its own declared name instead of a numeric code.
     */
    public static final Map<String, String> PROTO_VERSION_BY_NAME =
            Map.ofEntries(
                    Map.entry("SSL3_VERSION", "SSLv3.0"),
                    Map.entry("TLS1_VERSION", "TLSv1.0"),
                    Map.entry("TLS1_1_VERSION", "TLSv1.1"),
                    Map.entry("TLS1_2_VERSION", "TLSv1.2"),
                    Map.entry("TLS1_3_VERSION", "TLSv1.3"),
                    Map.entry("DTLS1_VERSION", "DTLSv1.0"),
                    Map.entry("DTLS1_2_VERSION", "DTLSv1.2"),
                    Map.entry("DTLS1_BAD_VER", "DTLSv1.0"));

    /** Widens an {@code int} unchanged; the default {@code codeMask}. */
    private static final IntUnaryOperator NO_MASK = code -> code;

    @Nonnull private final Map<Integer, String> byCode;
    @Nonnull private final Map<String, String> byName;
    @Nonnull private final IntUnaryOperator codeMask;
    @Nonnull private final BiFunction<String, AstNode, IValue<AstNode>> valueConstructor;

    public OpenSSLNidLookupFactory() {
        this(CURVE_BY_CODE, CURVE_BY_NAME);
    }

    public OpenSSLNidLookupFactory(
            @Nonnull Map<Integer, String> byCode, @Nonnull Map<String, String> byName) {
        this(byCode, byName, NO_MASK, ValueAction::new);
    }

    /**
     * @param codeMask applied to a numeric argument's {@code int} value before the {@code byCode}
     *     lookup (e.g. {@code code -> code & 0xFFFF} to drop width padding on a protocol-version
     *     code); {@link #NO_MASK} for callers with no such padding.
     * @param valueConstructor builds the {@link IValue} the resolved string is wrapped in (e.g.
     *     {@link ValueAction} for a plain identifier, {@link Protocol} for a protocol version).
     */
    public OpenSSLNidLookupFactory(
            @Nonnull Map<Integer, String> byCode,
            @Nonnull Map<String, String> byName,
            @Nonnull IntUnaryOperator codeMask,
            @Nonnull BiFunction<String, AstNode, IValue<AstNode>> valueConstructor) {
        this.byCode = byCode;
        this.byName = byName;
        this.codeMask = codeMask;
        this.valueConstructor = valueConstructor;
    }

    @Override
    @Nonnull
    public Optional<IValue<AstNode>> apply(@Nonnull ResolvedValue<Object, AstNode> resolvedValue) {
        final Object value = resolvedValue.value();
        String resolved = null;

        if (value instanceof Number number) {
            resolved = byCode.get(codeMask.applyAsInt(number.intValue()));
        } else if (value instanceof String str) {
            resolved = byName.get(str);
            if (resolved == null) {
                final Integer code = parseNumeric(str);
                if (code != null) {
                    resolved = byCode.get(codeMask.applyAsInt(code));
                }
            }
        }

        if (resolved != null) {
            LOGGER.debug("Resolved NID argument {} → \"{}\"", value, resolved);
            return Optional.of(valueConstructor.apply(resolved, resolvedValue.tree()));
        }
        LOGGER.debug(
                "Could not map NID argument value: {} ({})",
                value,
                value == null ? "null" : value.getClass().getSimpleName());
        return Optional.empty();
    }

    private static final Pattern INTEGER_SUFFIX_PATTERN = Pattern.compile("[uUlL]+$");

    /** Parses a decimal or hex ("0x19f") NID literal, tolerating integer suffixes. */
    private static Integer parseNumeric(@Nonnull String raw) {
        String s = INTEGER_SUFFIX_PATTERN.matcher(raw.trim()).replaceAll("");
        try {
            if (s.length() > 2 && (s.startsWith("0x") || s.startsWith("0X"))) {
                return Integer.parseInt(s.substring(2), 16);
            }
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
