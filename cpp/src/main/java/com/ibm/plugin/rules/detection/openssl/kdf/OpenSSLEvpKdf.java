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
package com.ibm.plugin.rules.detection.openssl.kdf;

import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.KeyDerivationFunctionContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLEvpMessageDigest;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLNameCanonicalizerFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for OpenSSL Key Derivation Functions (KDFs).
 *
 * <p>These rules detect KDF usage through the EVP_KDF API introduced in OpenSSL 3.0. Covers PBKDF2,
 * HKDF, Scrypt, TLS PRF, X963KDF, KBKDF, Argon2, and other KDFs.
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLEvpKdf {

    private static final String BUNDLE = "OpenSSL";

    // ====================================================================
    // PBKDF2 - Password-Based Key Derivation Function 2
    // ====================================================================

    private static final IDetectionRule<AstNode> PBKDF2_FETCH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBKDF2"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"PBKDF2\"")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // HKDF - HMAC-based Key Derivation Function
    // ====================================================================

    private static final IDetectionRule<AstNode> HKDF_FETCH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HKDF"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"HKDF\"")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Scrypt
    // ====================================================================

    private static final IDetectionRule<AstNode> SCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SCRYPT"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"SCRYPT\"")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // TLS1-PRF - TLS 1.0/1.1/1.2 Pseudo-Random Function
    // ====================================================================

    private static final IDetectionRule<AstNode> TLS1_PRF_FETCH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS1-PRF"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"TLS1-PRF\"")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // TLS13-KDF - TLS 1.3 Key Derivation Function
    // ====================================================================

    private static final IDetectionRule<AstNode> TLS13_KDF_FETCH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS13-KDF"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"TLS13-KDF\"")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // X963KDF - ANSI X9.63 Key Derivation Function
    // ====================================================================

    private static final IDetectionRule<AstNode> X963KDF_FETCH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("X963KDF"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"X963KDF\"")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // KBKDF - Key-Based Key Derivation Function (NIST SP 800-108)
    // ====================================================================

    private static final IDetectionRule<AstNode> KBKDF_FETCH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("KBKDF"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"KBKDF\"")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // SSHKDF - SSH Key Derivation Function
    // ====================================================================

    private static final IDetectionRule<AstNode> SSHKDF_FETCH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SSHKDF"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"SSHKDF\"")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Argon2 - Memory-hard password hashing and KDF
    // ====================================================================

    private static final IDetectionRule<AstNode> ARGON2D =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARGON2D"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"ARGON2D\"")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ARGON2I =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARGON2I"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"ARGON2I\"")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ARGON2ID =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARGON2ID"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"ARGON2ID\"")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // KRB5KDF - Kerberos 5 Key Derivation Function
    // ====================================================================

    private static final IDetectionRule<AstNode> KRB5KDF =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("KRB5KDF"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"KRB5KDF\"")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // X942KDF - X9.42 Key Derivation Function
    // ====================================================================

    // EVP_KDF_fetch("X942KDF-ASN1", ...) has no digest argument at the fetch call site - the real
    // digest (SHA-1, SHA-256, ...) is set later via EVP_KDF_CTX_set_params and surfaces as its own
    // DigestContext finding (see EVP_KDF_CTX_SET_PARAMS above), the same pattern as HMAC/CMAC/GMAC
    // fetch in OpenSSLEvpMac. A single X942KDF-ASN1 marker replaces what were two rules
    // (X942KDF_SHA1/X942KDF_SHA256) matching the identical literal and colliding
    // non-deterministically.
    private static final IDetectionRule<AstNode> X942KDF_ASN1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("X942KDF-ASN1"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"X942KDF-ASN1\"")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> X942KDF_CONCAT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("X942KDF-CONCAT"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"X942KDF-CONCAT\"")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // SSKDF - Single Step Key Derivation Function (NIST SP 800-56C)
    // ====================================================================

    private static final IDetectionRule<AstNode> SSKDF =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SSKDF"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"SSKDF\"")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // HMAC-DRBG-KDF - HMAC-based DRBG as KDF (NIST SP 800-90A)
    // ====================================================================

    private static final IDetectionRule<AstNode> HMAC_DRBG_KDF =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC-DRBG-KDF"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"HMAC-DRBG-KDF\"")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // PKCS12KDF - PKCS#12 Key Derivation Function
    // ====================================================================

    private static final IDetectionRule<AstNode> PKCS12KDF =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS12KDF"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"PKCS12KDF\"")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // PVKKDF - Microsoft PVK Key Derivation Function (Legacy)
    // ====================================================================

    private static final IDetectionRule<AstNode> PVKKDF =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PVKKDF"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"PVKKDF\"")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Legacy PBKDF2 functions
    // ====================================================================

    // int PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, iter, const EVP_MD *digest, keylen, out)
    // -
    // the digest at position 6 is traced back to its EVP_shaXXX()-style constructing call (same
    // mechanism as EVP_PKEY_CTX_SET_HKDF_MD below) and surfaces as its own DigestContext finding.
    private static final IDetectionRule<AstNode> PKCS5_PBKDF2_HMAC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS5_PBKDF2_HMAC")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBKDF2-HMAC"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpMessageDigest.rules())
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS5_PBKDF2_HMAC_SHA1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS5_PBKDF2_HMAC_SHA1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBKDF2-HMAC-SHA1"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // HKDF setters
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_HKDF_MD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_hkdf_md")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpMessageDigest.rules())
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_HKDF_MODE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_hkdf_mode")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HKDF-MODE"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // TLS1-PRF setters
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_TLS1_PRF_MD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_tls1_prf_md")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpMessageDigest.rules())
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // PKCS#12 KDF / MAC entry points
    // ====================================================================

    private static final IDetectionRule<AstNode> PKCS12_CREATE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS12"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS12_CREATE_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_create_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS12"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS12_CREATE_EX2 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_create_ex2")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS12"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS12_SET_MAC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_set_mac")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS12-MAC"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS12_PBE_KEYIVGEN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_PBE_keyivgen")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS12-PBE"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS12_PBE_KEYIVGEN_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_PBE_keyivgen_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS12-PBE"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS12_KEY_GEN_ASC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_key_gen_asc")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS12-KDF"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS12_KEY_GEN_ASC_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_key_gen_asc_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS12-KDF"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS12_KEY_GEN_UNI =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_key_gen_uni")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS12-KDF"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS12_KEY_GEN_UNI_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_key_gen_uni_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS12-KDF"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS12_KEY_GEN_UTF8 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_key_gen_utf8")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS12-KDF"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS12_KEY_GEN_UTF8_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_key_gen_utf8_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS12-KDF"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // EVP_KDF CTX/derive
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_KDF_CTX_NEW =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_CTX_new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("KDF-CTX"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // PKCS5 PBE keyivgen (legacy)
    // ====================================================================

    private static final IDetectionRule<AstNode> PKCS5_PBE_KEYIVGEN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS5_PBE_keyivgen")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBE-KEYIVGEN"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS5_PBE_KEYIVGEN_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS5_PBE_keyivgen_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBE-KEYIVGEN"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_KDF_CTX_SET_PARAMS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_CTX_set_params")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLParamsScannerFactory(
                                    "digest", OpenSSLNameCanonicalizerFactory.DIGEST_NAMES))
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLEvpKdf() {
        // nothing
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(
                // PBKDF2
                PBKDF2_FETCH,
                // HKDF
                HKDF_FETCH,
                // Scrypt
                SCRYPT,
                // TLS1-PRF
                TLS1_PRF_FETCH,
                // TLS13-KDF
                TLS13_KDF_FETCH,
                // X963KDF
                X963KDF_FETCH,
                // KBKDF
                KBKDF_FETCH,
                // SSHKDF
                SSHKDF_FETCH,
                // Argon2
                ARGON2D,
                ARGON2I,
                ARGON2ID,
                // KRB5KDF
                KRB5KDF,
                // X942KDF
                X942KDF_ASN1,
                X942KDF_CONCAT,
                // SSKDF
                SSKDF,
                // HMAC-DRBG-KDF
                HMAC_DRBG_KDF,
                // PKCS12KDF
                PKCS12KDF,
                // PVKKDF
                PVKKDF,
                // Legacy PBKDF2
                PKCS5_PBKDF2_HMAC,
                PKCS5_PBKDF2_HMAC_SHA1,
                // HKDF setters
                EVP_PKEY_CTX_SET_HKDF_MD,
                EVP_PKEY_CTX_SET_HKDF_MODE,
                // TLS1-PRF setters
                EVP_PKEY_CTX_SET_TLS1_PRF_MD,
                // PKCS#12 KDF / MAC entry points
                PKCS12_CREATE,
                PKCS12_CREATE_EX,
                PKCS12_CREATE_EX2,
                PKCS12_SET_MAC,
                PKCS12_PBE_KEYIVGEN,
                PKCS12_PBE_KEYIVGEN_EX,
                PKCS12_KEY_GEN_ASC,
                PKCS12_KEY_GEN_ASC_EX,
                PKCS12_KEY_GEN_UNI,
                PKCS12_KEY_GEN_UNI_EX,
                PKCS12_KEY_GEN_UTF8,
                PKCS12_KEY_GEN_UTF8_EX,
                // EVP_KDF CTX/derive
                EVP_KDF_CTX_NEW,
                // PKCS5 PBE keyivgen (legacy)
                PKCS5_PBE_KEYIVGEN,
                PKCS5_PBE_KEYIVGEN_EX,
                EVP_KDF_CTX_SET_PARAMS);
    }
}
