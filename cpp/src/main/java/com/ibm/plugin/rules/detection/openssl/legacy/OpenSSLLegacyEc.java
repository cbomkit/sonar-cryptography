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

import com.ibm.engine.model.context.KeyAgreementContext;
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
    // EC Key Management functions
    // ====================================================================

    private static final IDetectionRule<AstNode> EC_KEY_NEW =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EC_KEY_new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EC_KEY_NEW_BY_CURVE_NAME =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EC_KEY_new_by_curve_name")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EC_KEY_GENERATE_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EC_KEY_generate_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EC_KEY_CHECK_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EC_KEY_check_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EC_KEY_SET_PUBLIC_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EC_KEY_set_public_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EC_KEY_SET_PRIVATE_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EC_KEY_set_private_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

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
                    .buildForContext(new SignatureContext(SignatureContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ECDSA_VERIFY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("ECDSA_verify")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDSA-VERIFY"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext(SignatureContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ECDSA_DO_SIGN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("ECDSA_do_sign")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDSA-SIGN"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext(SignatureContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ECDSA_DO_VERIFY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("ECDSA_do_verify")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDSA-VERIFY"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext(SignatureContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ECDSA_SIGN_SETUP =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("ECDSA_sign_setup")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDSA-SIGN"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext(SignatureContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ECDSA_SIGN_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("ECDSA_sign_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDSA-SIGN"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext(SignatureContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ECDSA_DO_SIGN_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("ECDSA_do_sign_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDSA-SIGN"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext(SignatureContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ECDSA_SIZE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("ECDSA_size")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDSA"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext(SignatureContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // ECDH Key Agreement functions
    // ====================================================================

    private static final IDetectionRule<AstNode> ECDH_COMPUTE_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("ECDH_compute_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDH"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // EC Group/Curve functions
    // ====================================================================

    private static final IDetectionRule<AstNode> EC_GROUP_NEW_BY_CURVE_NAME =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EC_GROUP_new_by_curve_name")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EC_GROUP_NEW_CURVE_GFP =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EC_GROUP_new_curve_GFp")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC-GFP"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EC_GROUP_NEW_CURVE_GF2M =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EC_GROUP_new_curve_GF2m")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC-GF2M"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // EC Point Operation functions
    // ====================================================================

    private static final IDetectionRule<AstNode> EC_POINT_NEW =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EC_POINT_new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EC_POINT_MUL =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EC_POINT_mul")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLLegacyEc() {
        // nothing
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(
                // EC Key Management
                EC_KEY_NEW,
                EC_KEY_NEW_BY_CURVE_NAME,
                EC_KEY_GENERATE_KEY,
                EC_KEY_CHECK_KEY,
                EC_KEY_SET_PUBLIC_KEY,
                EC_KEY_SET_PRIVATE_KEY,
                // ECDSA Signatures
                ECDSA_SIGN,
                ECDSA_VERIFY,
                ECDSA_DO_SIGN,
                ECDSA_DO_VERIFY,
                ECDSA_SIGN_SETUP,
                ECDSA_SIGN_EX,
                ECDSA_DO_SIGN_EX,
                ECDSA_SIZE,
                // ECDH Key Agreement
                ECDH_COMPUTE_KEY,
                // EC Group/Curve
                EC_GROUP_NEW_BY_CURVE_NAME,
                EC_GROUP_NEW_CURVE_GFP,
                EC_GROUP_NEW_CURVE_GF2M,
                // EC Point Operations
                EC_POINT_NEW,
                EC_POINT_MUL);
    }
}
