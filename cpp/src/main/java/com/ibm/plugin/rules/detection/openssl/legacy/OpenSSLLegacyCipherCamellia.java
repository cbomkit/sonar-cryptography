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
package com.ibm.plugin.rules.detection.openssl.legacy;

import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;

/** Detection rules for OpenSSL legacy (pre-EVP) Camellia cipher APIs. */
@SuppressWarnings("java:S1192")
public final class OpenSSLLegacyCipherCamellia {

    private static final String BUNDLE = "OpenSSL";

    private static final IDetectionRule<AstNode> CAMELLIA_SET_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("Camellia_set_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CAMELLIA_ECB_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("Camellia_ecb_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-ECB"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CAMELLIA_CBC_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("Camellia_cbc_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-CBC"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CAMELLIA_CFB128_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("Camellia_cfb128_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-CFB128"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CAMELLIA_CFB1_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("Camellia_cfb1_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-CFB1"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CAMELLIA_CFB8_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("Camellia_cfb8_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-CFB8"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CAMELLIA_OFB128_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("Camellia_ofb128_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-OFB"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CAMELLIA_CTR128_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("Camellia_ctr128_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-CTR"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLLegacyCipherCamellia() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return List.of(
                CAMELLIA_SET_KEY,
                CAMELLIA_ECB_ENCRYPT,
                CAMELLIA_CBC_ENCRYPT,
                CAMELLIA_CFB128_ENCRYPT,
                CAMELLIA_CFB1_ENCRYPT,
                CAMELLIA_CFB8_ENCRYPT,
                CAMELLIA_OFB128_ENCRYPT,
                CAMELLIA_CTR128_ENCRYPT);
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLLegacyCipherCamellia::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
