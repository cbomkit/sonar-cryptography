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
 * Detection rules for OpenSSL EVP SM4 cipher algorithm specifiers.
 *
 * <p>Covers SM4 (the Chinese national standard cipher, GB/T 32907-2016) across all EVP modes (ECB,
 * CBC, CFB variants, OFB, CTR).
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLEvpCipherSm4 {

    private static final String BUNDLE = "OpenSSL";

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

    private OpenSSLEvpCipherSm4() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return List.of(
                // SM4
                EVP_SM4_ECB, EVP_SM4_CBC, EVP_SM4_CFB, EVP_SM4_CFB128, EVP_SM4_OFB, EVP_SM4_CTR);
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLEvpCipherSm4::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
