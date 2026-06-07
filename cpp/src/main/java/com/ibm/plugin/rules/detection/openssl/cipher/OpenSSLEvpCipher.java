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
 * Detection rules for OpenSSL EVP cipher algorithm specifiers.
 *
 * <p>These rules detect calls to OpenSSL functions that return EVP_CIPHER pointers, identifying the
 * specific cipher algorithm, key size, and mode of operation. Each function (e.g., {@code
 * EVP_aes_256_gcm()}) maps to a known cipher specification.
 *
 * <p>Covers all OpenSSL symmetric ciphers including AES, Camellia, ARIA, SM4, DES, ChaCha20,
 * Blowfish, CAST5, RC2/4/5, IDEA, and SEED.
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLEvpCipher {

    private static final String BUNDLE = "OpenSSL";

    // ====================================================================
    // AES (Advanced Encryption Standard)
    // ====================================================================

    // AES-128
    private static final IDetectionRule<AstNode> EVP_AES_128_CBC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_128_cbc")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-128-CBC"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_128_ECB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_128_ecb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-128-ECB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_128_GCM =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_128_gcm")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-128-GCM"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_128_CTR =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_128_ctr")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-128-CTR"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_128_CCM =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_128_ccm")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-128-CCM"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_128_CFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_128_cfb128")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-128-CFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_128_CFB1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_128_cfb1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-128-CFB1"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_128_CFB8 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_128_cfb8")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-128-CFB8"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_128_CFB128 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_128_cfb128")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-128-CFB128"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_128_OFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_128_ofb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-128-OFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_128_XTS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_128_xts")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-128-XTS"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_128_OCB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_128_ocb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-128-OCB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_128_WRAP =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_128_wrap")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-128-WRAP"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_128_WRAP_PAD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_128_wrap_pad")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-128-WRAP-PAD"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // AES-192
    private static final IDetectionRule<AstNode> EVP_AES_192_CBC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_192_cbc")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-192-CBC"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_192_ECB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_192_ecb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-192-ECB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_192_GCM =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_192_gcm")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-192-GCM"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_192_CTR =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_192_ctr")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-192-CTR"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_192_CCM =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_192_ccm")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-192-CCM"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_192_CFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_192_cfb128")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-192-CFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_192_CFB1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_192_cfb1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-192-CFB1"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_192_CFB8 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_192_cfb8")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-192-CFB8"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_192_CFB128 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_192_cfb128")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-192-CFB128"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_192_OFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_192_ofb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-192-OFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_192_OCB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_192_ocb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-192-OCB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_192_WRAP =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_192_wrap")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-192-WRAP"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_192_WRAP_PAD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_192_wrap_pad")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-192-WRAP-PAD"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // AES-256
    private static final IDetectionRule<AstNode> EVP_AES_256_CBC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_256_cbc")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-256-CBC"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_256_ECB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_256_ecb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-256-ECB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_256_GCM =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_256_gcm")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-256-GCM"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_256_CTR =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_256_ctr")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-256-CTR"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_256_CCM =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_256_ccm")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-256-CCM"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_256_CFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_256_cfb128")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-256-CFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_256_CFB1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_256_cfb1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-256-CFB1"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_256_CFB8 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_256_cfb8")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-256-CFB8"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_256_CFB128 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_256_cfb128")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-256-CFB128"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_256_OFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_256_ofb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-256-OFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_256_XTS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_256_xts")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-256-XTS"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_256_OCB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_256_ocb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-256-OCB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_256_WRAP =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_256_wrap")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-256-WRAP"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_256_WRAP_PAD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_256_wrap_pad")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-256-WRAP-PAD"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Camellia
    // ====================================================================

    // Camellia-128
    private static final IDetectionRule<AstNode> EVP_CAMELLIA_128_ECB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_camellia_128_ecb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-128-ECB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_CAMELLIA_128_CBC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_camellia_128_cbc")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-128-CBC"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_CAMELLIA_128_CFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_camellia_128_cfb128")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-128-CFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_CAMELLIA_128_CFB1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_camellia_128_cfb1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-128-CFB1"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_CAMELLIA_128_CFB8 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_camellia_128_cfb8")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-128-CFB8"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_CAMELLIA_128_CFB128 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_camellia_128_cfb128")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-128-CFB128"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_CAMELLIA_128_OFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_camellia_128_ofb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-128-OFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_CAMELLIA_128_CTR =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_camellia_128_ctr")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-128-CTR"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // Camellia-192
    private static final IDetectionRule<AstNode> EVP_CAMELLIA_192_ECB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_camellia_192_ecb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-192-ECB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_CAMELLIA_192_CBC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_camellia_192_cbc")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-192-CBC"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_CAMELLIA_192_CFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_camellia_192_cfb128")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-192-CFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_CAMELLIA_192_CFB1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_camellia_192_cfb1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-192-CFB1"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_CAMELLIA_192_CFB8 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_camellia_192_cfb8")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-192-CFB8"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_CAMELLIA_192_CFB128 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_camellia_192_cfb128")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-192-CFB128"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_CAMELLIA_192_OFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_camellia_192_ofb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-192-OFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_CAMELLIA_192_CTR =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_camellia_192_ctr")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-192-CTR"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // Camellia-256
    private static final IDetectionRule<AstNode> EVP_CAMELLIA_256_ECB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_camellia_256_ecb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-256-ECB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_CAMELLIA_256_CBC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_camellia_256_cbc")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-256-CBC"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_CAMELLIA_256_CFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_camellia_256_cfb128")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-256-CFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_CAMELLIA_256_CFB1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_camellia_256_cfb1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-256-CFB1"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_CAMELLIA_256_CFB8 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_camellia_256_cfb8")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-256-CFB8"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_CAMELLIA_256_CFB128 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_camellia_256_cfb128")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-256-CFB128"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_CAMELLIA_256_OFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_camellia_256_ofb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-256-OFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_CAMELLIA_256_CTR =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_camellia_256_ctr")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-256-CTR"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // ARIA
    // ====================================================================

    // ARIA-128
    private static final IDetectionRule<AstNode> EVP_ARIA_128_ECB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aria_128_ecb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARIA-128-ECB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_ARIA_128_CBC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aria_128_cbc")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARIA-128-CBC"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_ARIA_128_CFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aria_128_cfb128")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARIA-128-CFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_ARIA_128_CFB1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aria_128_cfb1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARIA-128-CFB1"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_ARIA_128_CFB8 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aria_128_cfb8")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARIA-128-CFB8"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_ARIA_128_CFB128 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aria_128_cfb128")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARIA-128-CFB128"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_ARIA_128_OFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aria_128_ofb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARIA-128-OFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_ARIA_128_CTR =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aria_128_ctr")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARIA-128-CTR"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_ARIA_128_GCM =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aria_128_gcm")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARIA-128-GCM"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_ARIA_128_CCM =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aria_128_ccm")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARIA-128-CCM"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ARIA-192
    private static final IDetectionRule<AstNode> EVP_ARIA_192_ECB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aria_192_ecb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARIA-192-ECB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_ARIA_192_CBC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aria_192_cbc")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARIA-192-CBC"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_ARIA_192_CFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aria_192_cfb128")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARIA-192-CFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_ARIA_192_CFB1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aria_192_cfb1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARIA-192-CFB1"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_ARIA_192_CFB8 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aria_192_cfb8")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARIA-192-CFB8"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_ARIA_192_CFB128 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aria_192_cfb128")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARIA-192-CFB128"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_ARIA_192_OFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aria_192_ofb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARIA-192-OFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_ARIA_192_CTR =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aria_192_ctr")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARIA-192-CTR"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_ARIA_192_GCM =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aria_192_gcm")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARIA-192-GCM"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_ARIA_192_CCM =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aria_192_ccm")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARIA-192-CCM"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ARIA-256
    private static final IDetectionRule<AstNode> EVP_ARIA_256_ECB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aria_256_ecb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARIA-256-ECB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_ARIA_256_CBC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aria_256_cbc")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARIA-256-CBC"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_ARIA_256_CFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aria_256_cfb128")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARIA-256-CFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_ARIA_256_CFB1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aria_256_cfb1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARIA-256-CFB1"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_ARIA_256_CFB8 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aria_256_cfb8")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARIA-256-CFB8"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_ARIA_256_CFB128 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aria_256_cfb128")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARIA-256-CFB128"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_ARIA_256_OFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aria_256_ofb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARIA-256-OFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_ARIA_256_CTR =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aria_256_ctr")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARIA-256-CTR"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_ARIA_256_GCM =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aria_256_gcm")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARIA-256-GCM"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_ARIA_256_CCM =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aria_256_ccm")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARIA-256-CCM"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // SM4 (Chinese National Standard)
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_SM4_ECB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_sm4_ecb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SM4-ECB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_SM4_CBC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_sm4_cbc")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SM4-CBC"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_SM4_CFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_sm4_cfb128")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SM4-CFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_SM4_CFB128 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_sm4_cfb128")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SM4-CFB128"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_SM4_OFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_sm4_ofb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SM4-OFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_SM4_CTR =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_sm4_ctr")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SM4-CTR"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // DES / 3DES
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_DES_CBC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_des_cbc")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DES-CBC"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DES_ECB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_des_ecb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DES-ECB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DES_EDE3_CBC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_des_ede3_cbc")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DESede3-CBC"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // Single DES additional modes
    private static final IDetectionRule<AstNode> EVP_DES_CFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_des_cfb64")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DES-CFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DES_CFB1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_des_cfb1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DES-CFB1"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DES_CFB8 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_des_cfb8")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DES-CFB8"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DES_CFB64 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_des_cfb64")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DES-CFB64"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DES_OFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_des_ofb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DES-OFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // 3DES EDE (2-key)
    private static final IDetectionRule<AstNode> EVP_DES_EDE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_des_ede")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DESede"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DES_EDE_ECB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_des_ede_ecb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DESede-ECB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DES_EDE_CBC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_des_ede_cbc")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DESede-CBC"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DES_EDE_CFB64 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_des_ede_cfb64")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DESede-CFB64"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DES_EDE_OFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_des_ede_ofb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DESede-OFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // 3DES EDE3 (3-key) additional modes
    private static final IDetectionRule<AstNode> EVP_DES_EDE3 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_des_ede3")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DESede3"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DES_EDE3_ECB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_des_ede3_ecb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DESede3-ECB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DES_EDE3_CFB1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_des_ede3_cfb1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DESede3-CFB1"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DES_EDE3_CFB8 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_des_ede3_cfb8")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DESede3-CFB8"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DES_EDE3_CFB64 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_des_ede3_cfb64")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DESede3-CFB64"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DES_EDE3_OFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_des_ede3_ofb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DESede3-OFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // DESX
    private static final IDetectionRule<AstNode> EVP_DESX_CBC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_desx_cbc")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DESX-CBC"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // EVP_des_ede3_wrap
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_DES_EDE3_WRAP =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_des_ede3_wrap")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DES-EDE3-WRAP"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Blowfish
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_BF_ECB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_bf_ecb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("BLOWFISH-ECB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_BF_CBC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_bf_cbc")
                    .shouldBeDetectedAs(new ValueActionFactory<>("BLOWFISH-CBC"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_BF_CFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_bf_cfb64")
                    .shouldBeDetectedAs(new ValueActionFactory<>("BLOWFISH-CFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_BF_CFB64 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_bf_cfb64")
                    .shouldBeDetectedAs(new ValueActionFactory<>("BLOWFISH-CFB64"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_BF_OFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_bf_ofb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("BLOWFISH-OFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // CAST5
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_CAST5_ECB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_cast5_ecb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAST5-ECB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_CAST5_CBC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_cast5_cbc")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAST5-CBC"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_CAST5_CFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_cast5_cfb64")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAST5-CFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_CAST5_CFB64 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_cast5_cfb64")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAST5-CFB64"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_CAST5_OFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_cast5_ofb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAST5-OFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // RC2
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_RC2_ECB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_rc2_ecb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RC2-ECB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_RC2_CBC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_rc2_cbc")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RC2-CBC"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_RC2_CFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_rc2_cfb64")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RC2-CFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_RC2_CFB64 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_rc2_cfb64")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RC2-CFB64"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_RC2_OFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_rc2_ofb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RC2-OFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_RC2_40_CBC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_rc2_40_cbc")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RC2-40-CBC"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_RC2_64_CBC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_rc2_64_cbc")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RC2-64-CBC"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // RC4 (Stream Cipher)
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_RC4 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_rc4")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RC4"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_RC4_40 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_rc4_40")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RC4-40"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_RC4_HMAC_MD5 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_rc4_hmac_md5")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RC4-HMAC-MD5"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // RC5
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_RC5_32_12_16_ECB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_rc5_32_12_16_ecb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RC5-ECB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_RC5_32_12_16_CBC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_rc5_32_12_16_cbc")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RC5-CBC"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_RC5_32_12_16_CFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_rc5_32_12_16_cfb64")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RC5-CFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_RC5_32_12_16_CFB64 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_rc5_32_12_16_cfb64")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RC5-CFB64"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_RC5_32_12_16_OFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_rc5_32_12_16_ofb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RC5-OFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // IDEA
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_IDEA_ECB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_idea_ecb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("IDEA-ECB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_IDEA_CBC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_idea_cbc")
                    .shouldBeDetectedAs(new ValueActionFactory<>("IDEA-CBC"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_IDEA_CFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_idea_cfb64")
                    .shouldBeDetectedAs(new ValueActionFactory<>("IDEA-CFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_IDEA_CFB64 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_idea_cfb64")
                    .shouldBeDetectedAs(new ValueActionFactory<>("IDEA-CFB64"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_IDEA_OFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_idea_ofb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("IDEA-OFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // SEED (Korean National Standard)
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_SEED_ECB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_seed_ecb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SEED-ECB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_SEED_CBC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_seed_cbc")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SEED-CBC"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_SEED_CFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_seed_cfb128")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SEED-CFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_SEED_CFB128 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_seed_cfb128")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SEED-CFB128"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_SEED_OFB =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_seed_ofb")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SEED-OFB"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // ChaCha20
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_CHACHA20 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_chacha20")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ChaCha20"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_CHACHA20_POLY1305 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_chacha20_poly1305")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ChaCha20-Poly1305"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // AES CBC-HMAC Combined Mode - TLS Encrypt-then-MAC
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_AES_128_CBC_HMAC_SHA1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_128_cbc_hmac_sha1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-128-CBC-HMAC-SHA1"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_256_CBC_HMAC_SHA1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_256_cbc_hmac_sha1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-256-CBC-HMAC-SHA1"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_128_CBC_HMAC_SHA256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_128_cbc_hmac_sha256")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-128-CBC-HMAC-SHA256"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_AES_256_CBC_HMAC_SHA256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_aes_256_cbc_hmac_sha256")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-256-CBC-HMAC-SHA256"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // NULL Cipher
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_ENC_NULL =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_enc_null")
                    .shouldBeDetectedAs(new ValueActionFactory<>("NULL"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Legacy lookup
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_GET_CIPHERBYNAME =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_get_cipherbyname")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CIPHER-BY-NAME"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // EVP cipher init
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_ENCRYPT_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_EncryptInit")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ENCRYPT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_ENCRYPT_INIT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_EncryptInit_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ENCRYPT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_ENCRYPT_INIT_EX2 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_EncryptInit_ex2")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ENCRYPT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DECRYPT_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DecryptInit")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DECRYPT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DECRYPT_INIT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DecryptInit_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DECRYPT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DECRYPT_INIT_EX2 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DecryptInit_ex2")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DECRYPT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_CIPHER_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CipherInit")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CIPHER-INIT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_CIPHER_INIT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CipherInit_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CIPHER-INIT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_CIPHER_INIT_EX2 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CipherInit_ex2")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CIPHER-INIT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // EVP_ASYM_CIPHER_fetch - Asymmetric cipher algorithm fetch
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_ASYM_CIPHER_FETCH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_ASYM_CIPHER_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ASYM-CIPHER"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // EVP_PKEY encrypt / decrypt
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_PKEY_ENCRYPT_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_encrypt_init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ENCRYPT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_ENCRYPT_INIT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_encrypt_init_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ENCRYPT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ENCRYPT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_DECRYPT_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_decrypt_init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DECRYPT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_DECRYPT_INIT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_decrypt_init_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DECRYPT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_DECRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_decrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DECRYPT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // RSA OAEP context setters
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_RSA_PADDING =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_rsa_padding")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PADDING"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_RSA_OAEP_MD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_rsa_oaep_md")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-OAEP-MD"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_RSA_OAEP_MD_NAME =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_rsa_oaep_md_name")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-OAEP-MD"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET0_RSA_OAEP_LABEL =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set0_rsa_oaep_label")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-OAEP-LABEL"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // CMS - Cryptographic Message Syntax (enveloped / encrypted data)
    // ====================================================================

    private static final IDetectionRule<AstNode> CMS_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMS_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMS-ENCRYPT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMS_ENCRYPT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMS_encrypt_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMS-ENCRYPT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMS_ENVELOPED_DATA_CREATE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMS_EnvelopedData_create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMS-ENVELOPED-DATA"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMS_ENVELOPED_DATA_CREATE_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMS_EnvelopedData_create_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMS-ENVELOPED-DATA"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMS_AUTH_ENVELOPED_DATA_CREATE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMS_AuthEnvelopedData_create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMS-AUTH-ENVELOPED-DATA"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMS_AUTH_ENVELOPED_DATA_CREATE_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMS_AuthEnvelopedData_create_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMS-AUTH-ENVELOPED-DATA"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMS_ENCRYPTED_DATA_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMS_EncryptedData_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMS-ENCRYPTED-DATA"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMS_ENCRYPTED_DATA_ENCRYPT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMS_EncryptedData_encrypt_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMS-ENCRYPTED-DATA"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMS_ENCRYPTED_DATA_SET1_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMS_EncryptedData_set1_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMS-ENCRYPTED-DATA-KEY"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMS_ADD0_RECIPIENT_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMS_add0_recipient_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMS-RECIPIENT-KEY"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // PKCS#7 encryption functions
    // ====================================================================

    private static final IDetectionRule<AstNode> PKCS7_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS7_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS7-ENCRYPT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS7_ENCRYPT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS7_encrypt_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS7-ENCRYPT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS7_SET_CIPHER =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS7_set_cipher")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS7-CIPHER"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLEvpCipher() {
        // nothing
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(
                // AES-128
                EVP_AES_128_CBC,
                EVP_AES_128_ECB,
                EVP_AES_128_GCM,
                EVP_AES_128_CTR,
                EVP_AES_128_CCM,
                EVP_AES_128_CFB,
                EVP_AES_128_CFB1,
                EVP_AES_128_CFB8,
                EVP_AES_128_CFB128,
                EVP_AES_128_OFB,
                EVP_AES_128_XTS,
                EVP_AES_128_OCB,
                EVP_AES_128_WRAP,
                EVP_AES_128_WRAP_PAD,
                // AES-192
                EVP_AES_192_CBC,
                EVP_AES_192_ECB,
                EVP_AES_192_GCM,
                EVP_AES_192_CTR,
                EVP_AES_192_CCM,
                EVP_AES_192_CFB,
                EVP_AES_192_CFB1,
                EVP_AES_192_CFB8,
                EVP_AES_192_CFB128,
                EVP_AES_192_OFB,
                EVP_AES_192_OCB,
                EVP_AES_192_WRAP,
                EVP_AES_192_WRAP_PAD,
                // AES-256
                EVP_AES_256_CBC,
                EVP_AES_256_ECB,
                EVP_AES_256_GCM,
                EVP_AES_256_CTR,
                EVP_AES_256_CCM,
                EVP_AES_256_CFB,
                EVP_AES_256_CFB1,
                EVP_AES_256_CFB8,
                EVP_AES_256_CFB128,
                EVP_AES_256_OFB,
                EVP_AES_256_XTS,
                EVP_AES_256_OCB,
                EVP_AES_256_WRAP,
                EVP_AES_256_WRAP_PAD,
                // Camellia-128
                EVP_CAMELLIA_128_ECB,
                EVP_CAMELLIA_128_CBC,
                EVP_CAMELLIA_128_CFB,
                EVP_CAMELLIA_128_CFB1,
                EVP_CAMELLIA_128_CFB8,
                EVP_CAMELLIA_128_CFB128,
                EVP_CAMELLIA_128_OFB,
                EVP_CAMELLIA_128_CTR,
                // Camellia-192
                EVP_CAMELLIA_192_ECB,
                EVP_CAMELLIA_192_CBC,
                EVP_CAMELLIA_192_CFB,
                EVP_CAMELLIA_192_CFB1,
                EVP_CAMELLIA_192_CFB8,
                EVP_CAMELLIA_192_CFB128,
                EVP_CAMELLIA_192_OFB,
                EVP_CAMELLIA_192_CTR,
                // Camellia-256
                EVP_CAMELLIA_256_ECB,
                EVP_CAMELLIA_256_CBC,
                EVP_CAMELLIA_256_CFB,
                EVP_CAMELLIA_256_CFB1,
                EVP_CAMELLIA_256_CFB8,
                EVP_CAMELLIA_256_CFB128,
                EVP_CAMELLIA_256_OFB,
                EVP_CAMELLIA_256_CTR,
                // ARIA-128
                EVP_ARIA_128_ECB,
                EVP_ARIA_128_CBC,
                EVP_ARIA_128_CFB,
                EVP_ARIA_128_CFB1,
                EVP_ARIA_128_CFB8,
                EVP_ARIA_128_CFB128,
                EVP_ARIA_128_OFB,
                EVP_ARIA_128_CTR,
                EVP_ARIA_128_GCM,
                EVP_ARIA_128_CCM,
                // ARIA-192
                EVP_ARIA_192_ECB,
                EVP_ARIA_192_CBC,
                EVP_ARIA_192_CFB,
                EVP_ARIA_192_CFB1,
                EVP_ARIA_192_CFB8,
                EVP_ARIA_192_CFB128,
                EVP_ARIA_192_OFB,
                EVP_ARIA_192_CTR,
                EVP_ARIA_192_GCM,
                EVP_ARIA_192_CCM,
                // ARIA-256
                EVP_ARIA_256_ECB,
                EVP_ARIA_256_CBC,
                EVP_ARIA_256_CFB,
                EVP_ARIA_256_CFB1,
                EVP_ARIA_256_CFB8,
                EVP_ARIA_256_CFB128,
                EVP_ARIA_256_OFB,
                EVP_ARIA_256_CTR,
                EVP_ARIA_256_GCM,
                EVP_ARIA_256_CCM,
                // SM4
                EVP_SM4_ECB,
                EVP_SM4_CBC,
                EVP_SM4_CFB,
                EVP_SM4_CFB128,
                EVP_SM4_OFB,
                EVP_SM4_CTR,
                // DES/3DES
                EVP_DES_CBC,
                EVP_DES_ECB,
                EVP_DES_CFB,
                EVP_DES_CFB1,
                EVP_DES_CFB8,
                EVP_DES_CFB64,
                EVP_DES_OFB,
                EVP_DES_EDE,
                EVP_DES_EDE_ECB,
                EVP_DES_EDE_CBC,
                EVP_DES_EDE_CFB64,
                EVP_DES_EDE_OFB,
                EVP_DES_EDE3,
                EVP_DES_EDE3_ECB,
                EVP_DES_EDE3_CBC,
                EVP_DES_EDE3_CFB1,
                EVP_DES_EDE3_CFB8,
                EVP_DES_EDE3_CFB64,
                EVP_DES_EDE3_OFB,
                EVP_DESX_CBC,
                EVP_DES_EDE3_WRAP,
                // Blowfish
                EVP_BF_ECB,
                EVP_BF_CBC,
                EVP_BF_CFB,
                EVP_BF_CFB64,
                EVP_BF_OFB,
                // CAST5
                EVP_CAST5_ECB,
                EVP_CAST5_CBC,
                EVP_CAST5_CFB,
                EVP_CAST5_CFB64,
                EVP_CAST5_OFB,
                // RC2
                EVP_RC2_ECB,
                EVP_RC2_CBC,
                EVP_RC2_CFB,
                EVP_RC2_CFB64,
                EVP_RC2_OFB,
                EVP_RC2_40_CBC,
                EVP_RC2_64_CBC,
                // RC4
                EVP_RC4,
                EVP_RC4_40,
                EVP_RC4_HMAC_MD5,
                // RC5
                EVP_RC5_32_12_16_ECB,
                EVP_RC5_32_12_16_CBC,
                EVP_RC5_32_12_16_CFB,
                EVP_RC5_32_12_16_CFB64,
                EVP_RC5_32_12_16_OFB,
                // IDEA
                EVP_IDEA_ECB,
                EVP_IDEA_CBC,
                EVP_IDEA_CFB,
                EVP_IDEA_CFB64,
                EVP_IDEA_OFB,
                // SEED
                EVP_SEED_ECB,
                EVP_SEED_CBC,
                EVP_SEED_CFB,
                EVP_SEED_CFB128,
                EVP_SEED_OFB,
                // ChaCha20
                EVP_CHACHA20,
                EVP_CHACHA20_POLY1305,
                // AES CBC-HMAC
                EVP_AES_128_CBC_HMAC_SHA1,
                EVP_AES_256_CBC_HMAC_SHA1,
                EVP_AES_128_CBC_HMAC_SHA256,
                EVP_AES_256_CBC_HMAC_SHA256,
                // NULL Cipher
                EVP_ENC_NULL,
                // Legacy lookup
                EVP_GET_CIPHERBYNAME,
                // EVP cipher init
                EVP_ENCRYPT_INIT,
                EVP_ENCRYPT_INIT_EX,
                EVP_ENCRYPT_INIT_EX2,
                EVP_DECRYPT_INIT,
                EVP_DECRYPT_INIT_EX,
                EVP_DECRYPT_INIT_EX2,
                EVP_CIPHER_INIT,
                EVP_CIPHER_INIT_EX,
                EVP_CIPHER_INIT_EX2,
                // EVP asymmetric cipher fetch
                EVP_ASYM_CIPHER_FETCH,
                // EVP_PKEY encrypt
                EVP_PKEY_ENCRYPT_INIT,
                EVP_PKEY_ENCRYPT_INIT_EX,
                EVP_PKEY_ENCRYPT,
                // EVP_PKEY decrypt
                EVP_PKEY_DECRYPT_INIT,
                EVP_PKEY_DECRYPT_INIT_EX,
                EVP_PKEY_DECRYPT,
                // RSA OAEP context setters
                EVP_PKEY_CTX_SET_RSA_PADDING,
                EVP_PKEY_CTX_SET_RSA_OAEP_MD,
                EVP_PKEY_CTX_SET_RSA_OAEP_MD_NAME,
                EVP_PKEY_CTX_SET0_RSA_OAEP_LABEL,
                // CMS enveloped / encrypted data
                CMS_ENCRYPT,
                CMS_ENCRYPT_EX,
                CMS_ENVELOPED_DATA_CREATE,
                CMS_ENVELOPED_DATA_CREATE_EX,
                CMS_AUTH_ENVELOPED_DATA_CREATE,
                CMS_AUTH_ENVELOPED_DATA_CREATE_EX,
                CMS_ENCRYPTED_DATA_ENCRYPT,
                CMS_ENCRYPTED_DATA_ENCRYPT_EX,
                CMS_ENCRYPTED_DATA_SET1_KEY,
                CMS_ADD0_RECIPIENT_KEY,
                // PKCS#7 encryption
                PKCS7_ENCRYPT,
                PKCS7_ENCRYPT_EX,
                PKCS7_SET_CIPHER);
    }
}
