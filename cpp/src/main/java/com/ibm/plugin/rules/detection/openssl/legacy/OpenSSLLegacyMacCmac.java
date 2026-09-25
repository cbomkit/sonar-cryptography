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
import com.ibm.plugin.rules.detection.openssl.cipher.OpenSSLEvpCipher;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;

/** Detection rules for OpenSSL legacy (pre-EVP) CMAC APIs. */
@SuppressWarnings("java:S1192")
public final class OpenSSLLegacyMacCmac {

    private static final String BUNDLE = "OpenSSL";

    private static final IDetectionRule<AstNode> CMAC_CTX_NEW =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMAC_CTX_new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMAC"))
                    .withAnyParameters()
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMAC_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMAC_Init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMAC"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpCipher.rules())
                    .withMethodParameter("*")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMAC_UPDATE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMAC_Update")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMAC"))
                    .withAnyParameters()
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMAC_FINAL =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMAC_Final")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMAC"))
                    .withAnyParameters()
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMAC_RESUME =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMAC_resume")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMAC"))
                    .withAnyParameters()
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLLegacyMacCmac() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return List.of(CMAC_CTX_NEW, CMAC_INIT, CMAC_UPDATE, CMAC_FINAL, CMAC_RESUME);
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLLegacyMacCmac::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
