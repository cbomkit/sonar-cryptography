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
import com.ibm.plugin.rules.detection.Memoize;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;

/**
 * Detection rules for OpenSSL EVP AES cipher algorithm specifiers.
 *
 * <p>Covers AES-128/192/256 across all EVP modes (CBC, ECB, GCM, CTR, CCM, CFB variants, OFB, XTS,
 * OCB, key wrap) plus the AES-CBC-HMAC combined TLS Encrypt-then-MAC ciphers.
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLEvpCipherAes {

    private static final String BUNDLE = "OpenSSL";

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

    private OpenSSLEvpCipherAes() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
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
                // AES CBC-HMAC Combined Mode - TLS Encrypt-then-MAC
                EVP_AES_128_CBC_HMAC_SHA1,
                EVP_AES_256_CBC_HMAC_SHA1,
                EVP_AES_128_CBC_HMAC_SHA256,
                EVP_AES_256_CBC_HMAC_SHA256);
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLEvpCipherAes::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
