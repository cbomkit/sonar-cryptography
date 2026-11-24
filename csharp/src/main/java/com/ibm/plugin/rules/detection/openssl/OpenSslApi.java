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
package com.ibm.plugin.rules.detection.openssl;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * The OpenSSL 3.x API surface these rules read, as one table per closed constant set.
 *
 * <p>Every entry was taken from the OpenSSL project's own man pages and public headers at tag
 * {@code openssl-3.5} -- the sources behind {@code https://docs.openssl.org/3.5/} -- not from
 * memory:
 *
 * <ul>
 *   <li>{@code include/openssl/evp.h} for the complete list of {@code const EVP_CIPHER
 *       *EVP_<name>(void)} and {@code const EVP_MD *EVP_<name>(void)} functions.
 *   <li>{@code include/openssl/prov_ssl.h} for the protocol version constants and their wire
 *       values, {@code doc/man3/SSL_CTX_set_min_proto_version.pod} for which of them are supported.
 *   <li>{@code doc/man3/SSL_CTX_new.pod} for the {@code *_method} family.
 *   <li>{@code include/openssl/rsa.h} and {@code doc/man3/EVP_PKEY_CTX_ctrl.pod} for the RSA
 *       padding constants and their values.
 *   <li>{@code include/openssl/obj_mac.h} for the curve NIDs, their numeric values and the short
 *       name each one stands for.
 *   <li>{@code include/openssl/core_names.h.in} ({@code OSSL_KDF_NAME_*}) for the KDF algorithm
 *       name strings.
 * </ul>
 *
 * <p>The tables serve two purposes at once, and that is the point of putting them here rather than
 * in the translator: the rule sets take their {@code forMethods} names from the key sets, and
 * {@code CSharpOpenSslContextTranslator} resolves a detection by looking the same key up again. A
 * name that is not in the table is therefore never matched <em>and</em> never translated, so the
 * closed-set guard cannot drift away from the rule.
 *
 * <p>Deliberate omissions are recorded beside the table they belong to. The rule throughout is that
 * a detail OpenSSL leaves to run time is not written down: {@code EVP_rc4()} and {@code
 * EVP_bf_cbc()} take a key length set later through {@code EVP_CIPHER_CTX_set_key_length}, so
 * neither carries one here, while {@code EVP_rc4_40()} and {@code EVP_rc2_40_cbc()} name theirs and
 * do.
 */
public final class OpenSslApi {

    private OpenSslApi() {
        // utility
    }

    /** Key length unknown at the call site, because OpenSSL lets it be set later. */
    public static final int KEY_LENGTH_UNSPECIFIED = 0;

    /**
     * A symmetric cipher as one {@code EVP_*} function names it: the algorithm, the key length in
     * bits where the name states one, and the mode token where the name states one.
     */
    public record SymmetricSpec(@Nonnull String algorithm, int keyBits, @Nullable String mode) {}

    /** A message digest as one {@code EVP_*} function names it. */
    public record DigestSpec(@Nonnull String algorithm, int digestSize) {}

    /** What an {@code SSL_METHOD}-returning function says about the protocol it speaks. */
    public record MethodSpec(@Nonnull String protocol, @Nullable String version) {}

    // =====================================================================
    // Symmetric ciphers: the EVP_<cipher>() functions
    // =====================================================================

    public static final String AES = "AES";
    public static final String ARIA = "ARIA";
    public static final String CAMELLIA = "CAMELLIA";
    public static final String CHACHA20 = "CHACHA20";
    public static final String CHACHA20_POLY1305 = "CHACHA20-POLY1305";
    public static final String DES = "DES";
    public static final String DES_EDE = "DES-EDE";
    public static final String DES_EDE3 = "DES-EDE3";
    public static final String RC2 = "RC2";
    public static final String RC4 = "RC4";
    public static final String RC5 = "RC5";
    public static final String BLOWFISH = "BLOWFISH";
    public static final String CAST5 = "CAST5";
    public static final String IDEA = "IDEA";
    public static final String SEED = "SEED";
    public static final String SM4 = "SM4";

    private static final String CBC = "CBC";
    private static final String ECB = "ECB";
    private static final String OFB = "OFB";
    private static final String CTR = "CTR";
    private static final String GCM = "GCM";
    private static final String CCM = "CCM";
    private static final String OCB = "OCB";
    private static final String XTS = "XTS";
    private static final String KW = "KW";
    private static final String KWP = "KWP";
    private static final String CFB1 = "CFB1";
    private static final String CFB8 = "CFB8";
    private static final String CFB64 = "CFB64";
    private static final String CFB128 = "CFB128";

    @Nonnull private static final Map<String, SymmetricSpec> CIPHERS = buildCiphers();

    @Nonnull
    private static Map<String, SymmetricSpec> buildCiphers() {
        final Map<String, SymmetricSpec> map = new LinkedHashMap<>();

        // AES: three key lengths across every mode evp.h declares, plus XTS, which exists for
        // 128 and 256 only and whose name states the length of the *pair* of keys.
        for (int bits : new int[] {128, 192, 256}) {
            map.put("EVP_aes_" + bits + "_cbc", new SymmetricSpec(AES, bits, CBC));
            map.put("EVP_aes_" + bits + "_ecb", new SymmetricSpec(AES, bits, ECB));
            map.put("EVP_aes_" + bits + "_ofb", new SymmetricSpec(AES, bits, OFB));
            map.put("EVP_aes_" + bits + "_ctr", new SymmetricSpec(AES, bits, CTR));
            map.put("EVP_aes_" + bits + "_gcm", new SymmetricSpec(AES, bits, GCM));
            map.put("EVP_aes_" + bits + "_ccm", new SymmetricSpec(AES, bits, CCM));
            map.put("EVP_aes_" + bits + "_ocb", new SymmetricSpec(AES, bits, OCB));
            map.put("EVP_aes_" + bits + "_cfb1", new SymmetricSpec(AES, bits, CFB1));
            map.put("EVP_aes_" + bits + "_cfb8", new SymmetricSpec(AES, bits, CFB8));
            map.put("EVP_aes_" + bits + "_cfb128", new SymmetricSpec(AES, bits, CFB128));
            map.put("EVP_aes_" + bits + "_wrap", new SymmetricSpec(AES, bits, KW));
            map.put("EVP_aes_" + bits + "_wrap_pad", new SymmetricSpec(AES, bits, KWP));
        }
        map.put("EVP_aes_128_xts", new SymmetricSpec(AES, 128, XTS));
        map.put("EVP_aes_256_xts", new SymmetricSpec(AES, 256, XTS));

        // ARIA and Camellia: the same shape, from the same header.
        for (int bits : new int[] {128, 192, 256}) {
            map.put("EVP_aria_" + bits + "_cbc", new SymmetricSpec(ARIA, bits, CBC));
            map.put("EVP_aria_" + bits + "_ecb", new SymmetricSpec(ARIA, bits, ECB));
            map.put("EVP_aria_" + bits + "_ofb", new SymmetricSpec(ARIA, bits, OFB));
            map.put("EVP_aria_" + bits + "_ctr", new SymmetricSpec(ARIA, bits, CTR));
            map.put("EVP_aria_" + bits + "_gcm", new SymmetricSpec(ARIA, bits, GCM));
            map.put("EVP_aria_" + bits + "_ccm", new SymmetricSpec(ARIA, bits, CCM));
            map.put("EVP_aria_" + bits + "_cfb1", new SymmetricSpec(ARIA, bits, CFB1));
            map.put("EVP_aria_" + bits + "_cfb8", new SymmetricSpec(ARIA, bits, CFB8));
            map.put("EVP_aria_" + bits + "_cfb128", new SymmetricSpec(ARIA, bits, CFB128));

            map.put("EVP_camellia_" + bits + "_cbc", new SymmetricSpec(CAMELLIA, bits, CBC));
            map.put("EVP_camellia_" + bits + "_ecb", new SymmetricSpec(CAMELLIA, bits, ECB));
            map.put("EVP_camellia_" + bits + "_ofb", new SymmetricSpec(CAMELLIA, bits, OFB));
            map.put("EVP_camellia_" + bits + "_ctr", new SymmetricSpec(CAMELLIA, bits, CTR));
            map.put("EVP_camellia_" + bits + "_cfb1", new SymmetricSpec(CAMELLIA, bits, CFB1));
            map.put("EVP_camellia_" + bits + "_cfb8", new SymmetricSpec(CAMELLIA, bits, CFB8));
            map.put("EVP_camellia_" + bits + "_cfb128", new SymmetricSpec(CAMELLIA, bits, CFB128));
        }

        // ChaCha20's key is 256 bits by construction; the Poly1305 variant is the AEAD and has no
        // mode of operation to name.
        map.put("EVP_chacha20", new SymmetricSpec(CHACHA20, 256, null));
        map.put("EVP_chacha20_poly1305", new SymmetricSpec(CHACHA20_POLY1305, 256, null));

        // DES. No key length is recorded: the mapper's own DES node carries 56 bits, and the
        // function name states nothing beyond the algorithm and the mode.
        map.put("EVP_des_cbc", new SymmetricSpec(DES, KEY_LENGTH_UNSPECIFIED, CBC));
        map.put("EVP_des_ecb", new SymmetricSpec(DES, KEY_LENGTH_UNSPECIFIED, ECB));
        map.put("EVP_des_ofb", new SymmetricSpec(DES, KEY_LENGTH_UNSPECIFIED, OFB));
        map.put("EVP_des_cfb1", new SymmetricSpec(DES, KEY_LENGTH_UNSPECIFIED, CFB1));
        map.put("EVP_des_cfb8", new SymmetricSpec(DES, KEY_LENGTH_UNSPECIFIED, CFB8));
        map.put("EVP_des_cfb64", new SymmetricSpec(DES, KEY_LENGTH_UNSPECIFIED, CFB64));

        // Two-key and three-key Triple DES. The distinction is in the function name -- `ede` is
        // K1,K2,K1 and `ede3` is K1,K2,K3 -- and it is the whole point of recording the key
        // length here: 112 and 168 bits of keying material respectively, which is what the
        // standards and CycloneDX count. The raw key buffers are 128 and 192 bits, parity
        // included, and are not what a bill of materials is asked for.
        map.put("EVP_des_ede", new SymmetricSpec(DES_EDE, 112, null));
        map.put("EVP_des_ede_cbc", new SymmetricSpec(DES_EDE, 112, CBC));
        map.put("EVP_des_ede_ecb", new SymmetricSpec(DES_EDE, 112, ECB));
        map.put("EVP_des_ede_ofb", new SymmetricSpec(DES_EDE, 112, OFB));
        map.put("EVP_des_ede_cfb64", new SymmetricSpec(DES_EDE, 112, CFB64));
        map.put("EVP_des_ede3", new SymmetricSpec(DES_EDE3, 168, null));
        map.put("EVP_des_ede3_cbc", new SymmetricSpec(DES_EDE3, 168, CBC));
        map.put("EVP_des_ede3_ecb", new SymmetricSpec(DES_EDE3, 168, ECB));
        map.put("EVP_des_ede3_ofb", new SymmetricSpec(DES_EDE3, 168, OFB));
        map.put("EVP_des_ede3_cfb1", new SymmetricSpec(DES_EDE3, 168, CFB1));
        map.put("EVP_des_ede3_cfb8", new SymmetricSpec(DES_EDE3, 168, CFB8));
        map.put("EVP_des_ede3_cfb64", new SymmetricSpec(DES_EDE3, 168, CFB64));
        map.put("EVP_des_ede3_wrap", new SymmetricSpec(DES_EDE3, 168, KW));

        // RC2. Only the two names that state a key length carry one; plain `EVP_rc2_*` defaults
        // to 128 bits but can be changed with EVP_CIPHER_CTX_set_key_length, so it is left open.
        map.put("EVP_rc2_cbc", new SymmetricSpec(RC2, KEY_LENGTH_UNSPECIFIED, CBC));
        map.put("EVP_rc2_ecb", new SymmetricSpec(RC2, KEY_LENGTH_UNSPECIFIED, ECB));
        map.put("EVP_rc2_ofb", new SymmetricSpec(RC2, KEY_LENGTH_UNSPECIFIED, OFB));
        map.put("EVP_rc2_cfb64", new SymmetricSpec(RC2, KEY_LENGTH_UNSPECIFIED, CFB64));
        map.put("EVP_rc2_40_cbc", new SymmetricSpec(RC2, 40, CBC));
        map.put("EVP_rc2_64_cbc", new SymmetricSpec(RC2, 64, CBC));

        // RC4 is a stream cipher, so there is no mode. `EVP_rc4_40` is the export-grade variant.
        map.put("EVP_rc4", new SymmetricSpec(RC4, KEY_LENGTH_UNSPECIFIED, null));
        map.put("EVP_rc4_40", new SymmetricSpec(RC4, 40, null));

        // RC5: the name fixes a 32-bit word, 12 rounds and a 16-byte (128-bit) key.
        map.put("EVP_rc5_32_12_16_cbc", new SymmetricSpec(RC5, 128, CBC));
        map.put("EVP_rc5_32_12_16_ecb", new SymmetricSpec(RC5, 128, ECB));
        map.put("EVP_rc5_32_12_16_ofb", new SymmetricSpec(RC5, 128, OFB));
        map.put("EVP_rc5_32_12_16_cfb64", new SymmetricSpec(RC5, 128, CFB64));

        // Blowfish and CAST5 both take a variable-length key, so none is recorded.
        map.put("EVP_bf_cbc", new SymmetricSpec(BLOWFISH, KEY_LENGTH_UNSPECIFIED, CBC));
        map.put("EVP_bf_ecb", new SymmetricSpec(BLOWFISH, KEY_LENGTH_UNSPECIFIED, ECB));
        map.put("EVP_bf_ofb", new SymmetricSpec(BLOWFISH, KEY_LENGTH_UNSPECIFIED, OFB));
        map.put("EVP_bf_cfb64", new SymmetricSpec(BLOWFISH, KEY_LENGTH_UNSPECIFIED, CFB64));
        map.put("EVP_cast5_cbc", new SymmetricSpec(CAST5, KEY_LENGTH_UNSPECIFIED, CBC));
        map.put("EVP_cast5_ecb", new SymmetricSpec(CAST5, KEY_LENGTH_UNSPECIFIED, ECB));
        map.put("EVP_cast5_ofb", new SymmetricSpec(CAST5, KEY_LENGTH_UNSPECIFIED, OFB));
        map.put("EVP_cast5_cfb64", new SymmetricSpec(CAST5, KEY_LENGTH_UNSPECIFIED, CFB64));

        // IDEA, SEED and SM4 all have a fixed 128-bit key.
        map.put("EVP_idea_cbc", new SymmetricSpec(IDEA, 128, CBC));
        map.put("EVP_idea_ecb", new SymmetricSpec(IDEA, 128, ECB));
        map.put("EVP_idea_ofb", new SymmetricSpec(IDEA, 128, OFB));
        map.put("EVP_idea_cfb64", new SymmetricSpec(IDEA, 128, CFB64));
        map.put("EVP_seed_cbc", new SymmetricSpec(SEED, 128, CBC));
        map.put("EVP_seed_ecb", new SymmetricSpec(SEED, 128, ECB));
        map.put("EVP_seed_ofb", new SymmetricSpec(SEED, 128, OFB));
        map.put("EVP_seed_cfb128", new SymmetricSpec(SEED, 128, CFB128));
        map.put("EVP_sm4_cbc", new SymmetricSpec(SM4, 128, CBC));
        map.put("EVP_sm4_ecb", new SymmetricSpec(SM4, 128, ECB));
        map.put("EVP_sm4_ofb", new SymmetricSpec(SM4, 128, OFB));
        map.put("EVP_sm4_ctr", new SymmetricSpec(SM4, 128, CTR));
        map.put("EVP_sm4_cfb128", new SymmetricSpec(SM4, 128, CFB128));

        // Deliberately absent, although evp.h declares them:
        //  - EVP_enc_null, the identity "cipher". The mapper has no node for "no encryption", and
        //    a component named NULL would read as an algorithm rather than as its absence.
        //  - EVP_desx_cbc (DES-X). No mapper model, and reporting it as DES would understate the
        //    key length while reporting it as DESede would overstate the construction.
        //  - EVP_aes_{128,256}_cbc_hmac_sha{1,256}, the TLS 1.0 record-layer stitched ciphers.
        //    They are AES-CBC with an integrated HMAC, which is two algorithms in one node, and
        //    the mapper cannot say that; reporting only the AES half would drop the MAC.
        //  - EVP_rc4_hmac_md5, for the same reason.
        //  - The CCM/OCB/GCM variants of ARIA and Camellia that evp.h does declare are included
        //    above; the ones it does not are simply not there.
        return Collections.unmodifiableMap(map);
    }

    /**
     * The OpenSSL algorithm-name strings accepted by {@code EVP_CIPHER_fetch} and {@code
     * EVP_get_cipherbyname}, mapped onto the same specifications.
     *
     * <p>Derived from the function table rather than written out again: OpenSSL's provider name for
     * a cipher is the function's own suffix in upper case with {@code -} between the parts, which
     * is exactly what the keys below are built from. Only the names that can be produced that way
     * are accepted, so a fetch of something this table does not know yields nothing.
     */
    @Nonnull
    private static final Map<String, SymmetricSpec> CIPHER_ALGORITHM_NAMES =
            buildCipherAlgorithmNames();

    @Nonnull
    private static Map<String, SymmetricSpec> buildCipherAlgorithmNames() {
        final Map<String, SymmetricSpec> map = new LinkedHashMap<>();
        for (Map.Entry<String, SymmetricSpec> entry : CIPHERS.entrySet()) {
            final String fetchName =
                    entry.getKey()
                            .substring("EVP_".length())
                            .replace("_", "-")
                            .toUpperCase(java.util.Locale.ROOT);
            map.putIfAbsent(fetchName, entry.getValue());
        }
        // The spellings OpenSSL's providers actually register that the mechanical rule above does
        // not produce. Verified against doc/man7/EVP_CIPHER-AES.pod and the provider's
        // ossl_cipher_* name tables.
        map.put("AES-128-CFB", new SymmetricSpec(AES, 128, CFB128));
        map.put("AES-192-CFB", new SymmetricSpec(AES, 192, CFB128));
        map.put("AES-256-CFB", new SymmetricSpec(AES, 256, CFB128));
        map.put("CHACHA20-POLY1305", new SymmetricSpec(CHACHA20_POLY1305, 256, null));
        map.put("DES-EDE3-CBC", new SymmetricSpec(DES_EDE3, 168, CBC));
        map.put("DES-EDE-CBC", new SymmetricSpec(DES_EDE, 112, CBC));
        return Collections.unmodifiableMap(map);
    }

    // =====================================================================
    // Message digests: the EVP_<md>() functions
    // =====================================================================

    public static final String SHA1 = "SHA1";
    public static final String SHA2 = "SHA2";
    public static final String SHA3 = "SHA3";
    public static final String SHAKE = "SHAKE";
    public static final String MD2 = "MD2";
    public static final String MD4 = "MD4";
    public static final String MD5 = "MD5";
    public static final String RIPEMD = "RIPEMD";
    public static final String BLAKE2B = "BLAKE2B";
    public static final String BLAKE2S = "BLAKE2S";
    public static final String SM3 = "SM3";
    public static final String WHIRLPOOL = "WHIRLPOOL";

    @Nonnull private static final Map<String, DigestSpec> DIGESTS = buildDigests();

    @Nonnull
    private static Map<String, DigestSpec> buildDigests() {
        final Map<String, DigestSpec> map = new LinkedHashMap<>();
        map.put("EVP_sha1", new DigestSpec(SHA1, 160));
        map.put("EVP_sha224", new DigestSpec(SHA2, 224));
        map.put("EVP_sha256", new DigestSpec(SHA2, 256));
        map.put("EVP_sha384", new DigestSpec(SHA2, 384));
        map.put("EVP_sha512", new DigestSpec(SHA2, 512));
        map.put("EVP_sha3_224", new DigestSpec(SHA3, 224));
        map.put("EVP_sha3_256", new DigestSpec(SHA3, 256));
        map.put("EVP_sha3_384", new DigestSpec(SHA3, 384));
        map.put("EVP_sha3_512", new DigestSpec(SHA3, 512));
        map.put("EVP_shake128", new DigestSpec(SHAKE, 128));
        map.put("EVP_shake256", new DigestSpec(SHAKE, 256));
        map.put("EVP_md2", new DigestSpec(MD2, 128));
        map.put("EVP_md4", new DigestSpec(MD4, 128));
        map.put("EVP_md5", new DigestSpec(MD5, 128));
        map.put("EVP_ripemd160", new DigestSpec(RIPEMD, 160));
        map.put("EVP_blake2b512", new DigestSpec(BLAKE2B, 512));
        map.put("EVP_blake2s256", new DigestSpec(BLAKE2S, 256));
        map.put("EVP_sm3", new DigestSpec(SM3, 256));
        map.put("EVP_whirlpool", new DigestSpec(WHIRLPOOL, 512));
        // SHA-512/224 and SHA-512/256 are truncated SHA-512. The mapper's SHA2 node spells a
        // truncation with a pre-hash child, which is not what these are, so they are recorded by
        // their own digest size under the SHA-2 family -- the name SHA2 composes is "SHA-224" and
        // "SHA-256", which understates the construction. They are therefore left out rather than
        // reported as something they are not.
        //
        // Also deliberately absent: EVP_md5_sha1 (the concatenated TLS 1.0/1.1 handshake hash,
        // which has no mapper model and is not one digest), EVP_mdc2 (no mapper model) and
        // EVP_md_null.
        return Collections.unmodifiableMap(map);
    }

    /**
     * The algorithm-name strings accepted by {@code EVP_MD_fetch} / {@code EVP_get_digestbyname}.
     */
    @Nonnull
    private static final Map<String, DigestSpec> DIGEST_ALGORITHM_NAMES =
            buildDigestAlgorithmNames();

    @Nonnull
    private static Map<String, DigestSpec> buildDigestAlgorithmNames() {
        final Map<String, DigestSpec> map = new LinkedHashMap<>();
        map.put("SHA1", new DigestSpec(SHA1, 160));
        map.put("SHA-1", new DigestSpec(SHA1, 160));
        map.put("SHA2-224", new DigestSpec(SHA2, 224));
        map.put("SHA2-256", new DigestSpec(SHA2, 256));
        map.put("SHA2-384", new DigestSpec(SHA2, 384));
        map.put("SHA2-512", new DigestSpec(SHA2, 512));
        map.put("SHA224", new DigestSpec(SHA2, 224));
        map.put("SHA256", new DigestSpec(SHA2, 256));
        map.put("SHA384", new DigestSpec(SHA2, 384));
        map.put("SHA512", new DigestSpec(SHA2, 512));
        map.put("SHA-224", new DigestSpec(SHA2, 224));
        map.put("SHA-256", new DigestSpec(SHA2, 256));
        map.put("SHA-384", new DigestSpec(SHA2, 384));
        map.put("SHA-512", new DigestSpec(SHA2, 512));
        map.put("SHA3-224", new DigestSpec(SHA3, 224));
        map.put("SHA3-256", new DigestSpec(SHA3, 256));
        map.put("SHA3-384", new DigestSpec(SHA3, 384));
        map.put("SHA3-512", new DigestSpec(SHA3, 512));
        map.put("SHAKE-128", new DigestSpec(SHAKE, 128));
        map.put("SHAKE-256", new DigestSpec(SHAKE, 256));
        map.put("SHAKE128", new DigestSpec(SHAKE, 128));
        map.put("SHAKE256", new DigestSpec(SHAKE, 256));
        map.put("MD2", new DigestSpec(MD2, 128));
        map.put("MD4", new DigestSpec(MD4, 128));
        map.put("MD5", new DigestSpec(MD5, 128));
        map.put("RIPEMD160", new DigestSpec(RIPEMD, 160));
        map.put("RIPEMD-160", new DigestSpec(RIPEMD, 160));
        map.put("BLAKE2B-512", new DigestSpec(BLAKE2B, 512));
        map.put("BLAKE2S-256", new DigestSpec(BLAKE2S, 256));
        map.put("SM3", new DigestSpec(SM3, 256));
        map.put("WHIRLPOOL", new DigestSpec(WHIRLPOOL, 512));
        return Collections.unmodifiableMap(map);
    }

    // =====================================================================
    // TLS: methods, version constants, cipher selection
    // =====================================================================

    public static final String TLS = "TLS";
    public static final String SSL = "SSL";
    public static final String DTLS = "DTLS";

    /**
     * The {@code SSL_METHOD}-returning functions of {@code doc/man3/SSL_CTX_new.pod}.
     *
     * <p>A version-flexible method ({@code TLS_method} and its {@code SSLv23_} alias, {@code
     * DTLS_method}) negotiates the best version both ends support, so it states the protocol and no
     * version -- which is exactly what the call site knows. The deprecated {@code TLSv1_x_method}
     * and {@code SSLv3_method} families are version-locked and state both.
     */
    @Nonnull private static final Map<String, MethodSpec> SSL_METHODS = buildSslMethods();

    @Nonnull
    private static Map<String, MethodSpec> buildSslMethods() {
        final Map<String, MethodSpec> map = new LinkedHashMap<>();
        for (String suffix : new String[] {"method", "server_method", "client_method"}) {
            map.put("TLS_" + suffix, new MethodSpec(TLS, null));
            map.put("SSLv23_" + suffix, new MethodSpec(TLS, null));
            map.put("TLSv1_" + suffix, new MethodSpec(TLS, "1.0"));
            map.put("TLSv1_1_" + suffix, new MethodSpec(TLS, "1.1"));
            map.put("TLSv1_2_" + suffix, new MethodSpec(TLS, "1.2"));
            map.put("SSLv3_" + suffix, new MethodSpec(SSL, "3"));
            map.put("SSLv2_" + suffix, new MethodSpec(SSL, "2"));
            map.put("DTLS_" + suffix, new MethodSpec(DTLS, null));
            map.put("DTLSv1_" + suffix, new MethodSpec(DTLS, "1.0"));
            map.put("DTLSv1_2_" + suffix, new MethodSpec(DTLS, "1.2"));
        }
        return Collections.unmodifiableMap(map);
    }

    /**
     * The protocol version constants of {@code include/openssl/prov_ssl.h}, by name and by wire
     * value.
     *
     * <p>Both spellings are accepted because both appear in P/Invoke code. A wrapper that declares
     * the constants on a class is read as a member access and reaches the translator as the name
     * {@code "TLS1_2_VERSION"}; one that declares them as C# {@code const int} fields is resolved
     * through the constant to the number {@code 0x0303}. The numbers are the versions as they go on
     * the wire, fixed by the TLS RFCs, so reading them is not a guess.
     *
     * <p>{@code 0} is absent on purpose. {@code SSL_CTX_set_min_proto_version(ctx, 0)} means "down
     * to whatever this build supports", which names no version at all.
     */
    @Nonnull
    private static final Map<String, MethodSpec> PROTOCOL_VERSIONS = buildProtocolVersions();

    @Nonnull
    private static Map<String, MethodSpec> buildProtocolVersions() {
        final Map<String, MethodSpec> map = new LinkedHashMap<>();
        map.put("SSL3_VERSION", new MethodSpec(SSL, "3"));
        map.put("TLS1_VERSION", new MethodSpec(TLS, "1.0"));
        map.put("TLS1_1_VERSION", new MethodSpec(TLS, "1.1"));
        map.put("TLS1_2_VERSION", new MethodSpec(TLS, "1.2"));
        map.put("TLS1_3_VERSION", new MethodSpec(TLS, "1.3"));
        map.put("DTLS1_VERSION", new MethodSpec(DTLS, "1.0"));
        map.put("DTLS1_2_VERSION", new MethodSpec(DTLS, "1.2"));
        map.put("768", new MethodSpec(SSL, "3")); // 0x0300
        map.put("769", new MethodSpec(TLS, "1.0")); // 0x0301
        map.put("770", new MethodSpec(TLS, "1.1")); // 0x0302
        map.put("771", new MethodSpec(TLS, "1.2")); // 0x0303
        map.put("772", new MethodSpec(TLS, "1.3")); // 0x0304
        map.put("65279", new MethodSpec(DTLS, "1.0")); // 0xFEFF
        map.put("65277", new MethodSpec(DTLS, "1.2")); // 0xFEFD
        return Collections.unmodifiableMap(map);
    }

    // =====================================================================
    // RSA padding
    // =====================================================================

    /**
     * The RSA padding constants of {@code include/openssl/rsa.h}, by name and by value.
     *
     * <p>The values are part of OpenSSL's ABI and have not moved since 0.9.x, so the numeric form a
     * C# {@code const int} resolves to is read as well as the name. {@code
     * RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING} (8) is absent: it is a decryption behaviour flag on
     * PKCS#1 v1.5, not a padding of its own, and reporting it as one would overstate it. {@code
     * RSA_PKCS1_PADDING_SIZE} is not a padding constant at all -- it is the 11-byte overhead -- and
     * is excluded for that reason.
     */
    @Nonnull private static final Map<String, String> RSA_PADDINGS = buildRsaPaddings();

    @Nonnull
    private static Map<String, String> buildRsaPaddings() {
        final Map<String, String> map = new LinkedHashMap<>();
        map.put("RSA_PKCS1_PADDING", "PKCS1");
        map.put("RSA_NO_PADDING", "NONE");
        map.put("RSA_PKCS1_OAEP_PADDING", "OAEP");
        map.put("RSA_X931_PADDING", "X9.31");
        map.put("RSA_PKCS1_PSS_PADDING", "PSS");
        // PKCS#1 v1.5 with the TLS-specific version check on decryption: the padding is PKCS#1.
        map.put("RSA_PKCS1_WITH_TLS_PADDING", "PKCS1");
        map.put("1", "PKCS1");
        map.put("3", "NONE");
        map.put("4", "OAEP");
        map.put("5", "X9.31");
        map.put("6", "PSS");
        map.put("7", "PKCS1");
        return Collections.unmodifiableMap(map);
    }

    // =====================================================================
    // Curve NIDs
    // =====================================================================

    /**
     * The elliptic-curve NIDs of {@code include/openssl/obj_mac.h}, by name and by value, each
     * mapped to the curve's OpenSSL short name ({@code SN_*}).
     *
     * <p>{@code NID_X9_62_prime256v1} is the NIST P-256 curve and {@code NID_X9_62_prime192v1} is
     * P-192; they are recorded under the short name OpenSSL itself prints, {@code prime256v1} and
     * {@code prime192v1}, rather than translated to the NIST spelling, so that what the CBOM says
     * is what the source says.
     */
    @Nonnull private static final Map<String, String> CURVE_NIDS = buildCurveNids();

    @Nonnull
    private static Map<String, String> buildCurveNids() {
        final Map<String, String> map = new LinkedHashMap<>();
        addCurve(map, "X9_62_prime192v1", 409, "prime192v1");
        addCurve(map, "X9_62_prime192v2", 410, "prime192v2");
        addCurve(map, "X9_62_prime192v3", 411, "prime192v3");
        addCurve(map, "X9_62_prime239v1", 412, "prime239v1");
        addCurve(map, "X9_62_prime239v2", 413, "prime239v2");
        addCurve(map, "X9_62_prime239v3", 414, "prime239v3");
        addCurve(map, "X9_62_prime256v1", 415, "prime256v1");
        addCurve(map, "secp112r1", 704, "secp112r1");
        addCurve(map, "secp112r2", 705, "secp112r2");
        addCurve(map, "secp128r1", 706, "secp128r1");
        addCurve(map, "secp128r2", 707, "secp128r2");
        addCurve(map, "secp160k1", 708, "secp160k1");
        addCurve(map, "secp160r1", 709, "secp160r1");
        addCurve(map, "secp160r2", 710, "secp160r2");
        addCurve(map, "secp192k1", 711, "secp192k1");
        addCurve(map, "secp224k1", 712, "secp224k1");
        addCurve(map, "secp224r1", 713, "secp224r1");
        addCurve(map, "secp256k1", 714, "secp256k1");
        addCurve(map, "secp384r1", 715, "secp384r1");
        addCurve(map, "secp521r1", 716, "secp521r1");
        addCurve(map, "sect163k1", 721, "sect163k1");
        addCurve(map, "sect163r1", 722, "sect163r1");
        addCurve(map, "sect163r2", 723, "sect163r2");
        addCurve(map, "sect193r1", 724, "sect193r1");
        addCurve(map, "sect193r2", 725, "sect193r2");
        addCurve(map, "sect233k1", 726, "sect233k1");
        addCurve(map, "sect233r1", 727, "sect233r1");
        addCurve(map, "sect239k1", 728, "sect239k1");
        addCurve(map, "sect283k1", 729, "sect283k1");
        addCurve(map, "sect283r1", 730, "sect283r1");
        addCurve(map, "sect409k1", 731, "sect409k1");
        addCurve(map, "sect409r1", 732, "sect409r1");
        addCurve(map, "sect571k1", 733, "sect571k1");
        addCurve(map, "sect571r1", 734, "sect571r1");
        addCurve(map, "brainpoolP160r1", 921, "brainpoolP160r1");
        addCurve(map, "brainpoolP192r1", 923, "brainpoolP192r1");
        addCurve(map, "brainpoolP224r1", 925, "brainpoolP224r1");
        addCurve(map, "brainpoolP256r1", 927, "brainpoolP256r1");
        addCurve(map, "brainpoolP320r1", 929, "brainpoolP320r1");
        addCurve(map, "brainpoolP384r1", 931, "brainpoolP384r1");
        addCurve(map, "brainpoolP512r1", 933, "brainpoolP512r1");
        return Collections.unmodifiableMap(map);
    }

    private static void addCurve(
            @Nonnull Map<String, String> map,
            @Nonnull String nidSuffix,
            int nid,
            @Nonnull String shortName) {
        map.put("NID_" + nidSuffix, shortName);
        map.put(Integer.toString(nid), shortName);
    }

    /**
     * The curve names {@code EVP_PKEY_CTX_set_group_name} and {@code EVP_PKEY_Q_keygen("EC", ...)}
     * accept, mapped to themselves plus the two spellings OpenSSL treats as aliases of P-256 and
     * friends. Only a name in this set is reported, so an unresolvable group name yields nothing.
     */
    @Nonnull private static final Map<String, String> CURVE_NAMES = buildCurveNames();

    @Nonnull
    private static Map<String, String> buildCurveNames() {
        final Map<String, String> map = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : CURVE_NIDS.entrySet()) {
            map.putIfAbsent(entry.getValue(), entry.getValue());
        }
        // The NIST aliases OpenSSL accepts for the three X9.62/SECG prime curves.
        map.put("P-192", "prime192v1");
        map.put("P-224", "secp224r1");
        map.put("P-256", "prime256v1");
        map.put("P-384", "secp384r1");
        map.put("P-521", "secp521r1");
        return Collections.unmodifiableMap(map);
    }

    // =====================================================================
    // KDFs
    // =====================================================================

    /**
     * The {@code EVP_KDF_fetch} algorithm names of {@code include/openssl/core_names.h.in}, for the
     * ones the mapper has a model for.
     *
     * <p>Left out, with no model to put them in: {@code TLS1-PRF}, {@code TLS13-KDF}, {@code
     * SSHKDF}, {@code ARGON2I}, {@code ARGON2ID}, {@code HMAC-DRBG-KDF} and {@code PVKKDF}. A
     * generic node named after the string would add the name and nothing else, and the name is
     * already in the finding's location keyword.
     */
    @Nonnull private static final Map<String, String> KDF_NAMES = buildKdfNames();

    @Nonnull
    private static Map<String, String> buildKdfNames() {
        final Map<String, String> map = new LinkedHashMap<>();
        map.put("PBKDF2", "PBKDF2");
        map.put("PBKDF1", "PBKDF1");
        map.put("SCRYPT", "SCRYPT");
        map.put("ID-SCRYPT", "SCRYPT");
        map.put("HKDF", "HKDF");
        map.put("SSKDF", "SSKDF");
        map.put("X942KDF-ASN1", "X942KDF");
        map.put("X942KDF-CONCAT", "X942KDF");
        map.put("X963KDF", "X963KDF");
        map.put("KBKDF", "KBKDF");
        map.put("KRB5KDF", "KRB5KDF");
        map.put("PKCS12KDF", "PKCS12KDF");
        return Collections.unmodifiableMap(map);
    }

    // =====================================================================
    // Accessors
    // =====================================================================

    @Nonnull
    public static Set<String> cipherFunctionNames() {
        return CIPHERS.keySet();
    }

    @Nonnull
    public static Set<String> digestFunctionNames() {
        return DIGESTS.keySet();
    }

    @Nonnull
    public static Set<String> sslMethodNames() {
        return SSL_METHODS.keySet();
    }

    @Nonnull
    public static Optional<SymmetricSpec> cipherFunction(@Nonnull String functionName) {
        return Optional.ofNullable(CIPHERS.get(functionName));
    }

    @Nonnull
    public static Optional<SymmetricSpec> cipherAlgorithmName(@Nonnull String algorithmName) {
        return Optional.ofNullable(
                CIPHER_ALGORITHM_NAMES.get(
                        algorithmName.trim().toUpperCase(java.util.Locale.ROOT)));
    }

    @Nonnull
    public static Optional<DigestSpec> digestFunction(@Nonnull String functionName) {
        return Optional.ofNullable(DIGESTS.get(functionName));
    }

    @Nonnull
    public static Optional<DigestSpec> digestAlgorithmName(@Nonnull String algorithmName) {
        return Optional.ofNullable(
                DIGEST_ALGORITHM_NAMES.get(
                        algorithmName.trim().toUpperCase(java.util.Locale.ROOT)));
    }

    @Nonnull
    public static Optional<MethodSpec> sslMethod(@Nonnull String functionName) {
        return Optional.ofNullable(SSL_METHODS.get(functionName));
    }

    @Nonnull
    public static Optional<MethodSpec> protocolVersion(@Nonnull String nameOrValue) {
        return Optional.ofNullable(PROTOCOL_VERSIONS.get(nameOrValue.trim()));
    }

    @Nonnull
    public static Optional<String> rsaPadding(@Nonnull String nameOrValue) {
        return Optional.ofNullable(RSA_PADDINGS.get(nameOrValue.trim()));
    }

    @Nonnull
    public static Optional<String> curveNid(@Nonnull String nameOrValue) {
        return Optional.ofNullable(CURVE_NIDS.get(nameOrValue.trim()));
    }

    @Nonnull
    public static Optional<String> curveName(@Nonnull String name) {
        return Optional.ofNullable(CURVE_NAMES.get(name.trim()));
    }

    /**
     * The MACs {@code EVP_MAC_fetch} can be asked for, and that this project can name.
     *
     * <p>OpenSSL 3.5 ships nine MAC implementations. Five are here. The four that are not:
     *
     * <ul>
     *   <li>{@code GMAC} -- the mapper has GMAC only as a cipher <em>mode</em>, not as an algorithm
     *       of its own, so there is no node to report. A GMAC is AES-GCM used as a MAC, and naming
     *       it AES would state an encryption that is not happening.
     *   <li>{@code BLAKE2BMAC} and {@code BLAKE2SMAC} -- the mapper has BLAKE2b and BLAKE2s as
     *       message digests. A keyed MAC is not a digest, and reporting the digest node would say
     *       the code hashes where it authenticates.
     * </ul>
     *
     * <p>Names are matched case-insensitively because OpenSSL's own fetch is: {@code "hmac"} and
     * {@code "HMAC"} reach the same implementation.
     */
    @Nonnull
    private static final Map<String, String> MAC_NAMES =
            Map.ofEntries(
                    Map.entry("HMAC", "HMAC"),
                    Map.entry("CMAC", "CMAC"),
                    Map.entry("KMAC-128", "KMAC-128"),
                    Map.entry("KMAC128", "KMAC-128"),
                    Map.entry("KMAC-256", "KMAC-256"),
                    Map.entry("KMAC256", "KMAC-256"),
                    Map.entry("POLY1305", "Poly1305"),
                    Map.entry("SIPHASH", "SipHash"));

    @Nonnull
    public static Optional<String> macName(@Nonnull String algorithmName) {
        return Optional.ofNullable(
                MAC_NAMES.get(algorithmName.trim().toUpperCase(java.util.Locale.ROOT)));
    }

    @Nonnull
    public static Optional<String> kdfName(@Nonnull String algorithmName) {
        return Optional.ofNullable(
                KDF_NAMES.get(algorithmName.trim().toUpperCase(java.util.Locale.ROOT)));
    }
}
