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
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for OpenSSL legacy MAC (Message Authentication Code) APIs.
 *
 * <p>These rules detect MAC operations using the legacy (pre-EVP) APIs. These APIs are deprecated
 * but still widely used in existing codebases.
 *
 * <p>Covers: HMAC, CMAC
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLLegacyMac {

    private static final String BUNDLE = "OpenSSL";

    // ====================================================================
    // Legacy HMAC functions
    // ====================================================================

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
                    .withAnyParameters()
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> HMAC_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("HMAC_Init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC"))
                    .withAnyParameters()
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
                    .withAnyParameters()
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Legacy CMAC functions
    // ====================================================================

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
                    .withAnyParameters()
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

    // ====================================================================
    // Legacy Poly1305 functions
    // ====================================================================

    private static final IDetectionRule<AstNode> POLY1305_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("Poly1305_Init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("POLY1305"))
                    .withAnyParameters()
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> POLY1305_UPDATE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("Poly1305_Update")
                    .shouldBeDetectedAs(new ValueActionFactory<>("POLY1305"))
                    .withAnyParameters()
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> POLY1305_FINAL =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("Poly1305_Final")
                    .shouldBeDetectedAs(new ValueActionFactory<>("POLY1305"))
                    .withAnyParameters()
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLLegacyMac() {
        // nothing
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(
                // HMAC
                HMAC_CTX_NEW,
                HMAC_CTX_RESET,
                HMAC_CTX_COPY,
                HMAC_INIT_EX,
                HMAC_INIT,
                HMAC_UPDATE,
                HMAC_FINAL,
                HMAC,
                // CMAC
                CMAC_CTX_NEW,
                CMAC_INIT,
                CMAC_UPDATE,
                CMAC_FINAL,
                CMAC_RESUME,
                // Poly1305
                POLY1305_INIT,
                POLY1305_UPDATE,
                POLY1305_FINAL);
    }
}
