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

/** Detection rules for OpenSSL EVP RC2 cipher algorithm specifiers. */
@SuppressWarnings("java:S1192")
public final class OpenSSLEvpCipherRc2 {

    private static final String BUNDLE = "OpenSSL";

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

    private OpenSSLEvpCipherRc2() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return List.of(
                EVP_RC2_ECB,
                EVP_RC2_CBC,
                EVP_RC2_CFB,
                EVP_RC2_CFB64,
                EVP_RC2_OFB,
                EVP_RC2_40_CBC,
                EVP_RC2_64_CBC);
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLEvpCipherRc2::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
