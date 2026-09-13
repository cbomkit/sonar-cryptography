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
 * Detection rules for OpenSSL EVP Camellia cipher algorithm specifiers.
 *
 * <p>Covers Camellia-128/192/256 across all EVP modes (ECB, CBC, CFB variants, OFB, CTR).
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLEvpCipherCamellia {

    private static final String BUNDLE = "OpenSSL";

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

    private OpenSSLEvpCipherCamellia() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return List.of(
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
                EVP_CAMELLIA_256_CTR);
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLEvpCipherCamellia::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
