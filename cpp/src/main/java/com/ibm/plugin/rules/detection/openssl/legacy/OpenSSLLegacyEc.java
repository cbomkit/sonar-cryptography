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

import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for OpenSSL legacy EC APIs.
 *
 * <p>These rules detect direct EC operations using the legacy (pre-EVP) APIs from ec.h. These APIs
 * are deprecated but still widely used in existing codebases.
 *
 * <p>Covers: EC key management, ECDSA signatures, ECDH key agreement, EC group/curve, EC point
 * operations
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLLegacyEc {

    private static final String BUNDLE = "OpenSSL";

    // ====================================================================
    // ECDSA Signature functions
    // ====================================================================

    private static final IDetectionRule<AstNode> ECDSA_SIGN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("ECDSA_sign")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDSA-SIGN"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ECDSA_DO_SIGN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("ECDSA_do_sign")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDSA-SIGN"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ECDSA_SIGN_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("ECDSA_sign_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDSA-SIGN"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ECDSA_DO_SIGN_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("ECDSA_do_sign_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDSA-SIGN"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Key Generation
    // ====================================================================

    private static final IDetectionRule<AstNode> EC_KEY_GENERATE_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EC_KEY_generate_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EC_KEY_NEW_BY_CURVE_NAME =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EC_KEY_new_by_curve_name")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EC_KEY_NEW_BY_CURVE_NAME_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EC_KEY_new_by_curve_name_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EC_KEY_SET_GROUP =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EC_KEY_set_group")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EC_GROUP_NEW_CURVE_GFP =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EC_GROUP_new_curve_GFp")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EC_GROUP_NEW_CURVE_GF2M =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EC_GROUP_new_curve_GF2m")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EC_GROUP_NEW_BY_CURVE_NAME =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EC_GROUP_new_by_curve_name")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EC_GROUP_NEW_BY_CURVE_NAME_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EC_GROUP_new_by_curve_name_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EC_GROUP_NEW_FROM_PARAMS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EC_GROUP_new_from_params")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EC_GROUP_NEW_FROM_ECPARAMETERS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EC_GROUP_new_from_ecparameters")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EC_GROUP_NEW_FROM_ECPKPARAMETERS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EC_GROUP_new_from_ecpkparameters")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLLegacyEc() {
        // nothing
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(
                // ECDSA Signatures
                ECDSA_SIGN,
                ECDSA_SIGN_EX,
                ECDSA_DO_SIGN,
                ECDSA_DO_SIGN_EX,
                // Key Generation
                EC_KEY_GENERATE_KEY,
                EC_KEY_NEW_BY_CURVE_NAME,
                EC_KEY_NEW_BY_CURVE_NAME_EX,
                EC_KEY_SET_GROUP,
                EC_GROUP_NEW_CURVE_GFP,
                EC_GROUP_NEW_CURVE_GF2M,
                EC_GROUP_NEW_BY_CURVE_NAME,
                EC_GROUP_NEW_BY_CURVE_NAME_EX,
                EC_GROUP_NEW_FROM_PARAMS,
                EC_GROUP_NEW_FROM_ECPARAMETERS,
                EC_GROUP_NEW_FROM_ECPKPARAMETERS);
    }
}
