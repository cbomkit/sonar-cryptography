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
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for OpenSSL legacy DH (Diffie-Hellman) APIs.
 *
 * <p>These rules detect direct DH operations using the legacy (pre-EVP) APIs from dh.h. These APIs
 * are deprecated but still widely used in existing codebases.
 *
 * <p>Covers: Key/Parameter Generation, Key Agreement, Predefined Groups (RFC 5114), Size/Info
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLLegacyDh {

    private static final String BUNDLE = "OpenSSL";

    // ====================================================================
    // Key/Parameter Generation functions
    // ====================================================================

    private static final IDetectionRule<AstNode> DH_NEW =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DH_new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DH"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DH_GENERATE_PARAMETERS_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DH_generate_parameters_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DH"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DH_GENERATE_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DH_generate_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DH"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DH_CHECK =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DH_check")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DH"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DH_CHECK_PARAMS_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DH_check_params_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DH"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DH_CHECK_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DH_check_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DH"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DH_CHECK_PUB_KEY_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DH_check_pub_key_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DH"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Key Agreement functions
    // ====================================================================

    private static final IDetectionRule<AstNode> DH_COMPUTE_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DH_compute_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DH"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DH_COMPUTE_KEY_PADDED =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DH_compute_key_padded")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DH"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Predefined Groups (RFC 5114) functions
    // ====================================================================

    private static final IDetectionRule<AstNode> DH_GET_1024_160 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DH_get_1024_160")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DH-1024-160"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DH_GET_2048_224 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DH_get_2048_224")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DH-2048-224"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DH_GET_2048_256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DH_get_2048_256")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DH-2048-256"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Size/Info functions
    // ====================================================================

    private static final IDetectionRule<AstNode> DH_SIZE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DH_size")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DH"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DH_BITS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DH_bits")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DH"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DH_SECURITY_BITS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DH_security_bits")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DH"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLLegacyDh() {
        // nothing
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(
                // Key/Parameter Generation
                DH_NEW,
                DH_GENERATE_PARAMETERS_EX,
                DH_GENERATE_KEY,
                DH_CHECK,
                DH_CHECK_PARAMS_EX,
                DH_CHECK_EX,
                DH_CHECK_PUB_KEY_EX,
                // Key Agreement
                DH_COMPUTE_KEY,
                DH_COMPUTE_KEY_PADDED,
                // Predefined Groups (RFC 5114)
                DH_GET_1024_160,
                DH_GET_2048_224,
                DH_GET_2048_256,
                // Size/Info
                DH_SIZE,
                DH_BITS,
                DH_SECURITY_BITS);
    }
}
