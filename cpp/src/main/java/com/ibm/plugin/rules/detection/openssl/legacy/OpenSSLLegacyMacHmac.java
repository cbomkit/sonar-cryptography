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

import com.ibm.engine.model.context.MacContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLEvpMessageDigest;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;

/** Detection rules for OpenSSL legacy (pre-EVP) HMAC APIs. */
@SuppressWarnings("java:S1192")
public final class OpenSSLLegacyMacHmac {

    private static final String BUNDLE = "OpenSSL";

    private static final IDetectionRule<AstNode> HMAC_CTX_NEW =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("HMAC_CTX_new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC"))
                    .withoutParameters()
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> HMAC_CTX_RESET =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("HMAC_CTX_reset")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC"))
                    .withAnyParameters()
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> HMAC_CTX_COPY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("HMAC_CTX_copy")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC"))
                    .withAnyParameters()
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> HMAC_INIT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("HMAC_Init_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpMessageDigest.rules())
                    .withMethodParameter("*")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> HMAC_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("HMAC_Init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpMessageDigest.rules())
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> HMAC_UPDATE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("HMAC_Update")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC"))
                    .withAnyParameters()
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> HMAC_FINAL =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("HMAC_Final")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC"))
                    .withAnyParameters()
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> HMAC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("HMAC")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC"))
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpMessageDigest.rules())
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLLegacyMacHmac() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return List.of(
                HMAC_CTX_NEW,
                HMAC_CTX_RESET,
                HMAC_CTX_COPY,
                HMAC_INIT_EX,
                HMAC_INIT,
                HMAC_UPDATE,
                HMAC_FINAL,
                HMAC);
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLLegacyMacHmac::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
