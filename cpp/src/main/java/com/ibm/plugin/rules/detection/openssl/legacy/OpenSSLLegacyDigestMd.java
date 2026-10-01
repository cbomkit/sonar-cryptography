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

/** Detection rules for OpenSSL legacy (pre-EVP) MD2/MD4/MD5/MDC2 digest APIs. */
@SuppressWarnings("java:S1192")
public final class OpenSSLLegacyDigestMd {

    private static final String BUNDLE = "OpenSSL";

    private static final IDetectionRule<AstNode> MD2 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("MD2")
                    .shouldBeDetectedAs(new ValueActionFactory<>("MD2"))
                    .withAnyParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> MD2_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("MD2_Init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("MD2"))
                    .withAnyParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> MD4 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("MD4")
                    .shouldBeDetectedAs(new ValueActionFactory<>("MD4"))
                    .withAnyParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> MD4_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("MD4_Init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("MD4"))
                    .withAnyParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> MD5_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("MD5_Init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("MD5"))
                    .withAnyParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> MD5 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("MD5")
                    .shouldBeDetectedAs(new ValueActionFactory<>("MD5"))
                    .withAnyParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> MDC2 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("MDC2")
                    .shouldBeDetectedAs(new ValueActionFactory<>("MDC2"))
                    .withAnyParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> MDC2_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("MDC2_Init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("MDC2"))
                    .withAnyParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLLegacyDigestMd() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return List.of(
                // MD2
                MD2,
                MD2_INIT,
                // MD4
                MD4,
                MD4_INIT,
                // MD5
                MD5_INIT,
                MD5,
                // MDC2
                MDC2,
                MDC2_INIT);
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLLegacyDigestMd::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
