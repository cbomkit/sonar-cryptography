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

import com.ibm.engine.model.context.KeyDerivationFunctionContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
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

    private static final IDetectionRule<AstNode> PBKDF2_HMAC_SHA1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBKDF2-HMAC-SHA1"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"PBKDF2\"")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PBKDF2_HMAC_SHA256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBKDF2-HMAC-SHA256"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"PBKDF2\"")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PBKDF2_HMAC_SHA384 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBKDF2-HMAC-SHA384"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"PBKDF2\"")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PBKDF2_HMAC_SHA512 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBKDF2-HMAC-SHA512"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"PBKDF2\"")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // HKDF - HMAC-based Key Derivation Function
    // ====================================================================

    private static final IDetectionRule<AstNode> HKDF_SHA1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HKDF-SHA1"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"HKDF\"")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> HKDF_SHA256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HKDF-SHA256"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"HKDF\"")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> HKDF_SHA384 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HKDF-SHA384"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"HKDF\"")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> HKDF_SHA512 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HKDF-SHA512"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"HKDF\"")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> HKDF_SHA3_256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HKDF-SHA3-256"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"HKDF\"")
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
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // TLS1-PRF - TLS 1.0/1.1/1.2 Pseudo-Random Function
    // ====================================================================

    private static final IDetectionRule<AstNode> TLS1_PRF_MD5_SHA1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS1-PRF-MD5-SHA1"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"TLS1-PRF\"")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> TLS1_PRF_SHA256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS1-PRF-SHA256"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"TLS1-PRF\"")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> TLS1_PRF_SHA384 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS1-PRF-SHA384"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"TLS1-PRF\"")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> TLS1_PRF_SHA512 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS1-PRF-SHA512"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"TLS1-PRF\"")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // TLS13-KDF - TLS 1.3 Key Derivation Function
    // ====================================================================

    private static final IDetectionRule<AstNode> TLS13_KDF_SHA256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS13-KDF-SHA256"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"TLS13-KDF\"")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> TLS13_KDF_SHA384 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS13-KDF-SHA384"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"TLS13-KDF\"")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> TLS13_KDF_SHA512 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS13-KDF-SHA512"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"TLS13-KDF\"")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // X963KDF - ANSI X9.63 Key Derivation Function
    // ====================================================================

    private static final IDetectionRule<AstNode> X963KDF_SHA1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("X963KDF-SHA1"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"X963KDF\"")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> X963KDF_SHA224 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("X963KDF-SHA224"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"X963KDF\"")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> X963KDF_SHA256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("X963KDF-SHA256"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"X963KDF\"")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> X963KDF_SHA384 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("X963KDF-SHA384"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"X963KDF\"")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> X963KDF_SHA512 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("X963KDF-SHA512"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"X963KDF\"")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // KBKDF - Key-Based Key Derivation Function (NIST SP 800-108)
    // ====================================================================

    private static final IDetectionRule<AstNode> KBKDF_HMAC_SHA1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("KBKDF-HMAC-SHA1"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"KBKDF\"")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> KBKDF_HMAC_SHA256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("KBKDF-HMAC-SHA256"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"KBKDF\"")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> KBKDF_HMAC_SHA384 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("KBKDF-HMAC-SHA384"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"KBKDF\"")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> KBKDF_HMAC_SHA512 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("KBKDF-HMAC-SHA512"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"KBKDF\"")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> KBKDF_CMAC_AES128 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("KBKDF-CMAC-AES128"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"KBKDF\"")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> KBKDF_CMAC_AES256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("KBKDF-CMAC-AES256"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"KBKDF\"")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // SSHKDF - SSH Key Derivation Function
    // ====================================================================

    private static final IDetectionRule<AstNode> SSHKDF_SHA1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SSHKDF-SHA1"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"SSHKDF\"")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSHKDF_SHA256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SSHKDF-SHA256"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"SSHKDF\"")
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
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // X942KDF - X9.42 Key Derivation Function
    // ====================================================================

    private static final IDetectionRule<AstNode> X942KDF_SHA1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("X942KDF-SHA1"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"X942KDF-ASN1\"")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> X942KDF_SHA256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("X942KDF-SHA256"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"X942KDF-ASN1\"")
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
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // PBKDF1 - Password-Based Key Derivation Function 1 (legacy)
    // ====================================================================

    private static final IDetectionRule<AstNode> PBKDF1_MD5 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS5_PBKDF1_MD5")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBKDF1-MD5"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PBKDF1_SHA1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS5_PBKDF1_SHA1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBKDF1-SHA1"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Legacy PBKDF2 functions
    // ====================================================================

    private static final IDetectionRule<AstNode> PKCS5_PBKDF2_HMAC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS5_PBKDF2_HMAC")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBKDF2-HMAC"))
                    .withAnyParameters()
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

    private OpenSSLEvpKdf() {
        // nothing
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(
                // PBKDF2
                PBKDF2_HMAC_SHA1,
                PBKDF2_HMAC_SHA256,
                PBKDF2_HMAC_SHA384,
                PBKDF2_HMAC_SHA512,
                // HKDF
                HKDF_SHA1,
                HKDF_SHA256,
                HKDF_SHA384,
                HKDF_SHA512,
                HKDF_SHA3_256,
                // Scrypt
                SCRYPT,
                // TLS1-PRF
                TLS1_PRF_MD5_SHA1,
                TLS1_PRF_SHA256,
                TLS1_PRF_SHA384,
                TLS1_PRF_SHA512,
                // TLS13-KDF
                TLS13_KDF_SHA256,
                TLS13_KDF_SHA384,
                TLS13_KDF_SHA512,
                // X963KDF
                X963KDF_SHA1,
                X963KDF_SHA224,
                X963KDF_SHA256,
                X963KDF_SHA384,
                X963KDF_SHA512,
                // KBKDF
                KBKDF_HMAC_SHA1,
                KBKDF_HMAC_SHA256,
                KBKDF_HMAC_SHA384,
                KBKDF_HMAC_SHA512,
                KBKDF_CMAC_AES128,
                KBKDF_CMAC_AES256,
                // SSHKDF
                SSHKDF_SHA1,
                SSHKDF_SHA256,
                // Argon2
                ARGON2D,
                ARGON2I,
                ARGON2ID,
                // KRB5KDF
                KRB5KDF,
                // X942KDF
                X942KDF_SHA1,
                X942KDF_SHA256,
                X942KDF_CONCAT,
                // SSKDF
                SSKDF,
                // HMAC-DRBG-KDF
                HMAC_DRBG_KDF,
                // PKCS12KDF
                PKCS12KDF,
                // PVKKDF
                PVKKDF,
                // PBKDF1 (legacy)
                PBKDF1_MD5,
                PBKDF1_SHA1,
                // Legacy PBKDF2
                PKCS5_PBKDF2_HMAC,
                PKCS5_PBKDF2_HMAC_SHA1);
    }
}
