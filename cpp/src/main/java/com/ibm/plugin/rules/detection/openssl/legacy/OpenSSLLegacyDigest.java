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
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for OpenSSL legacy digest/hash APIs.
 *
 * <p>These rules detect direct hash operations using the legacy (pre-EVP) APIs. These APIs are
 * deprecated but still widely used in existing codebases.
 *
 * <p>Covers: MD5, SHA-1, SHA-2 family (SHA-224, SHA-256, SHA-384, SHA-512), RIPEMD-160
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLLegacyDigest {

    private static final String BUNDLE = "OpenSSL";

    // ====================================================================
    // Legacy MD5 functions
    // ====================================================================

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

    // ====================================================================
    // Legacy SHA-1 functions
    // ====================================================================

    private static final IDetectionRule<AstNode> SHA1_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SHA1_Init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA-1"))
                    .withAnyParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SHA1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SHA1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA-1"))
                    .withAnyParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Legacy SHA-224 functions
    // ====================================================================

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

    // ====================================================================
    // Legacy SHA-256 functions
    // ====================================================================

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

    // ====================================================================
    // Legacy SHA-384 functions
    // ====================================================================

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

    // ====================================================================
    // Legacy SHA-512 functions
    // ====================================================================

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

    // ====================================================================
    // Legacy RIPEMD-160 functions
    // ====================================================================

    private static final IDetectionRule<AstNode> RIPEMD160_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RIPEMD160_Init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RIPEMD160"))
                    .withAnyParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RIPEMD160 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RIPEMD160")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RIPEMD160"))
                    .withAnyParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // WHIRLPOOL (deprecated, legacy provider)
    // ====================================================================

    private static final IDetectionRule<AstNode> WHIRLPOOL =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("WHIRLPOOL")
                    .shouldBeDetectedAs(new ValueActionFactory<>("WHIRLPOOL"))
                    .withAnyParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> WHIRLPOOL_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("WHIRLPOOL_Init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("WHIRLPOOL"))
                    .withAnyParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // MD2 / MD4 / MDC2 (deprecated, legacy provider)
    // ====================================================================

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

    private OpenSSLLegacyDigest() {
        // nothing
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(
                // MD5
                MD5_INIT,
                MD5,
                // SHA-1
                SHA1_INIT,
                SHA1,
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
                SHA512,
                // RIPEMD-160
                RIPEMD160_INIT,
                RIPEMD160,
                // WHIRLPOOL
                WHIRLPOOL,
                WHIRLPOOL_INIT,
                // MD2 / MD4 / MDC2
                MD2,
                MD2_INIT,
                MD4,
                MD4_INIT,
                MDC2,
                MDC2_INIT);
    }
}
