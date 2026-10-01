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
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/**
 * Detection rules for OpenSSL legacy digest/hash APIs.
 *
 * <p>These rules detect direct hash operations using the legacy (pre-EVP) APIs. These APIs are
 * deprecated but still widely used in existing codebases.
 *
 * <p>The MD (MD2/MD4/MD5/MDC2) and SHA-2 (SHA-224/256/384/512) families live in their own {@code
 * OpenSSLLegacyDigest<Family>} classes; this class holds the remaining single-algorithm legacy
 * digests (SHA-1, RIPEMD-160, WHIRLPOOL) and aggregates every family's rules in {@link #rules()}.
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLLegacyDigest {

    private static final String BUNDLE = "OpenSSL";

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

    private OpenSSLLegacyDigest() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return Stream.of(
                        OpenSSLLegacyDigestMd.rules().stream(),
                        OpenSSLLegacyDigestSha2.rules().stream(),
                        directRules().stream())
                .flatMap(i -> i)
                .toList();
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> directRules() {
        return List.of(
                // Legacy SHA-1 functions
                SHA1_INIT,
                SHA1,
                // Legacy RIPEMD-160 functions
                RIPEMD160_INIT,
                RIPEMD160,
                // WHIRLPOOL (deprecated, legacy provider)
                WHIRLPOOL,
                WHIRLPOOL_INIT);
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLLegacyDigest::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
