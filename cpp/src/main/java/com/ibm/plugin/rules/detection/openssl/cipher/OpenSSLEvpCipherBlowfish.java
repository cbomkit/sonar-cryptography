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

/** Detection rules for OpenSSL EVP Blowfish cipher algorithm specifiers. */
@SuppressWarnings("java:S1192")
public final class OpenSSLEvpCipherBlowfish {

    private static final String BUNDLE = "OpenSSL";

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

    private OpenSSLEvpCipherBlowfish() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return List.of(EVP_BF_ECB, EVP_BF_CBC, EVP_BF_CFB, EVP_BF_CFB64, EVP_BF_OFB);
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLEvpCipherBlowfish::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
