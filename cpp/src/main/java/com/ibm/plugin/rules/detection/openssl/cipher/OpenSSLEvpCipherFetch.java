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

import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for OpenSSL provider-only cipher modes accessible via EVP_CIPHER_fetch.
 *
 * <p>These cipher modes don't have convenience EVP_* functions and must be accessed through the
 * provider API using string identifiers. Covers modern AEAD modes (AES-SIV, AES-GCM-SIV), key
 * wrapping variants, and encrypt-then-MAC constructions.
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLEvpCipherFetch {

    private static final String BUNDLE = "OpenSSL";

    // ====================================================================
    // AES-SIV - Synthetic IV Mode (RFC 5297)
    // ====================================================================

    private static final IDetectionRule<AstNode> AES_128_SIV =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CIPHER_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-128-SIV"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"AES-128-SIV\"")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> AES_192_SIV =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CIPHER_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-192-SIV"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"AES-192-SIV\"")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> AES_256_SIV =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CIPHER_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-256-SIV"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"AES-256-SIV\"")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // AES-GCM-SIV - Nonce-Misuse Resistant AEAD (RFC 8452)
    // ====================================================================

    private static final IDetectionRule<AstNode> AES_128_GCM_SIV =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CIPHER_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-128-GCM-SIV"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"AES-128-GCM-SIV\"")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> AES_192_GCM_SIV =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CIPHER_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-192-GCM-SIV"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"AES-192-GCM-SIV\"")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> AES_256_GCM_SIV =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CIPHER_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-256-GCM-SIV"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"AES-256-GCM-SIV\"")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // AES CBC-CTS - Ciphertext Stealing Mode
    // ====================================================================

    private static final IDetectionRule<AstNode> AES_128_CBC_CTS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CIPHER_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-128-CBC-CTS"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"AES-128-CBC-CTS\"")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> AES_192_CBC_CTS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CIPHER_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-192-CBC-CTS"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"AES-192-CBC-CTS\"")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> AES_256_CBC_CTS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CIPHER_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-256-CBC-CTS"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"AES-256-CBC-CTS\"")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // AES WRAP-INV - Inverted Key Wrap (RFC 3394)
    // ====================================================================

    private static final IDetectionRule<AstNode> AES_128_WRAP_INV =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CIPHER_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-128-WRAP-INV"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"AES-128-WRAP-INV\"")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> AES_192_WRAP_INV =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CIPHER_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-192-WRAP-INV"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"AES-192-WRAP-INV\"")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> AES_256_WRAP_INV =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CIPHER_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-256-WRAP-INV"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"AES-256-WRAP-INV\"")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // AES WRAP-PAD-INV - Inverted Padded Key Wrap (RFC 5649)
    // ====================================================================

    private static final IDetectionRule<AstNode> AES_128_WRAP_PAD_INV =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CIPHER_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-128-WRAP-PAD-INV"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"AES-128-WRAP-PAD-INV\"")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> AES_192_WRAP_PAD_INV =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CIPHER_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-192-WRAP-PAD-INV"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"AES-192-WRAP-PAD-INV\"")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> AES_256_WRAP_PAD_INV =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CIPHER_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-256-WRAP-PAD-INV"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"AES-256-WRAP-PAD-INV\"")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // AES ETM - Encrypt-Then-MAC Variants (3 key sizes × 3 hash variants)
    // ====================================================================

    private static final IDetectionRule<AstNode> AES_128_CBC_HMAC_SHA1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CIPHER_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-128-CBC-HMAC-SHA1"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"AES-128-CBC-HMAC-SHA1\"")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> AES_128_CBC_HMAC_SHA256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CIPHER_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-128-CBC-HMAC-SHA256"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"AES-128-CBC-HMAC-SHA256\"")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> AES_192_CBC_HMAC_SHA1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CIPHER_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-192-CBC-HMAC-SHA1"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"AES-192-CBC-HMAC-SHA1\"")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> AES_192_CBC_HMAC_SHA256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CIPHER_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-192-CBC-HMAC-SHA256"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"AES-192-CBC-HMAC-SHA256\"")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> AES_256_CBC_HMAC_SHA1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CIPHER_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-256-CBC-HMAC-SHA1"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"AES-256-CBC-HMAC-SHA1\"")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> AES_256_CBC_HMAC_SHA256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CIPHER_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-256-CBC-HMAC-SHA256"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"AES-256-CBC-HMAC-SHA256\"")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // AES ETM - Encrypt-then-MAC for TLS (RFC 7366)
    // ====================================================================

    private static final IDetectionRule<AstNode> AES_128_CBC_HMAC_SHA1_ETM =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CIPHER_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-128-CBC-HMAC-SHA1-ETM"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"AES-128-CBC-HMAC-SHA1-ETM\"")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> AES_192_CBC_HMAC_SHA1_ETM =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CIPHER_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-192-CBC-HMAC-SHA1-ETM"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"AES-192-CBC-HMAC-SHA1-ETM\"")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> AES_256_CBC_HMAC_SHA1_ETM =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CIPHER_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-256-CBC-HMAC-SHA1-ETM"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"AES-256-CBC-HMAC-SHA1-ETM\"")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> AES_128_CBC_HMAC_SHA256_ETM =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CIPHER_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-128-CBC-HMAC-SHA256-ETM"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"AES-128-CBC-HMAC-SHA256-ETM\"")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> AES_192_CBC_HMAC_SHA256_ETM =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CIPHER_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-192-CBC-HMAC-SHA256-ETM"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"AES-192-CBC-HMAC-SHA256-ETM\"")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> AES_256_CBC_HMAC_SHA256_ETM =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CIPHER_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-256-CBC-HMAC-SHA256-ETM"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"AES-256-CBC-HMAC-SHA256-ETM\"")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> AES_128_CBC_HMAC_SHA512_ETM =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CIPHER_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-128-CBC-HMAC-SHA512-ETM"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"AES-128-CBC-HMAC-SHA512-ETM\"")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> AES_192_CBC_HMAC_SHA512_ETM =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CIPHER_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-192-CBC-HMAC-SHA512-ETM"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"AES-192-CBC-HMAC-SHA512-ETM\"")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> AES_256_CBC_HMAC_SHA512_ETM =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CIPHER_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-256-CBC-HMAC-SHA512-ETM"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"AES-256-CBC-HMAC-SHA512-ETM\"")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Camellia CBC-CTS - Ciphertext Stealing Mode
    // ====================================================================

    private static final IDetectionRule<AstNode> CAMELLIA_128_CBC_CTS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CIPHER_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-128-CBC-CTS"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"CAMELLIA-128-CBC-CTS\"")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CAMELLIA_192_CBC_CTS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CIPHER_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-192-CBC-CTS"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"CAMELLIA-192-CBC-CTS\"")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CAMELLIA_256_CBC_CTS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CIPHER_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-256-CBC-CTS"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"CAMELLIA-256-CBC-CTS\"")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLEvpCipherFetch() {
        // nothing
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(
                // AES-SIV
                AES_128_SIV,
                AES_192_SIV,
                AES_256_SIV,
                // AES-GCM-SIV
                AES_128_GCM_SIV,
                AES_192_GCM_SIV,
                AES_256_GCM_SIV,
                // AES CBC-CTS
                AES_128_CBC_CTS,
                AES_192_CBC_CTS,
                AES_256_CBC_CTS,
                // AES WRAP-INV
                AES_128_WRAP_INV,
                AES_192_WRAP_INV,
                AES_256_WRAP_INV,
                // AES WRAP-PAD-INV
                AES_128_WRAP_PAD_INV,
                AES_192_WRAP_PAD_INV,
                AES_256_WRAP_PAD_INV,
                // AES CBC-HMAC (non-ETM)
                AES_128_CBC_HMAC_SHA1,
                AES_128_CBC_HMAC_SHA256,
                AES_192_CBC_HMAC_SHA1,
                AES_192_CBC_HMAC_SHA256,
                AES_256_CBC_HMAC_SHA1,
                AES_256_CBC_HMAC_SHA256,
                // AES ETM (Encrypt-then-MAC)
                AES_128_CBC_HMAC_SHA1_ETM,
                AES_192_CBC_HMAC_SHA1_ETM,
                AES_256_CBC_HMAC_SHA1_ETM,
                AES_128_CBC_HMAC_SHA256_ETM,
                AES_192_CBC_HMAC_SHA256_ETM,
                AES_256_CBC_HMAC_SHA256_ETM,
                AES_128_CBC_HMAC_SHA512_ETM,
                AES_192_CBC_HMAC_SHA512_ETM,
                AES_256_CBC_HMAC_SHA512_ETM,
                // Camellia CBC-CTS
                CAMELLIA_128_CBC_CTS,
                CAMELLIA_192_CBC_CTS,
                CAMELLIA_256_CBC_CTS);
    }
}
