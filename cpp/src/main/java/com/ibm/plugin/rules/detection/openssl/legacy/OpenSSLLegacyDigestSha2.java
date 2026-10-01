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

import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;

/**
 * Detection rules for OpenSSL legacy (pre-EVP) SHA-2 family digest APIs.
 *
 * <p>Covers SHA-224, SHA-256, SHA-384, SHA-512.
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLLegacyDigestSha2 {

    private static final String BUNDLE = "OpenSSL";

    private static final IDetectionRule<AstNode> SHA224_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SHA224_Init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA-224"))
                    .withAnyParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SHA224 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SHA224")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA-224"))
                    .withAnyParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SHA256_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SHA256_Init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA-256"))
                    .withAnyParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SHA256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SHA256")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA-256"))
                    .withAnyParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SHA384_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SHA384_Init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA-384"))
                    .withAnyParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SHA384 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SHA384")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA-384"))
                    .withAnyParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SHA512_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SHA512_Init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA-512"))
                    .withAnyParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SHA512 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SHA512")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA-512"))
                    .withAnyParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLLegacyDigestSha2() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return List.of(
                // SHA-224
                SHA224_INIT,
                SHA224,
                // SHA-256
                SHA256_INIT,
                SHA256,
                // SHA-384
                SHA384_INIT,
                SHA384,
                // SHA-512
                SHA512_INIT,
                SHA512);
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLLegacyDigestSha2::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
