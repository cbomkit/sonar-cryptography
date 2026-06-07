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
 * Detection rules for OpenSSL legacy DSA APIs.
 *
 * <p>These rules detect direct DSA operations using the legacy (pre-EVP) APIs from dsa.h. These
 * APIs are deprecated but still widely used in existing codebases.
 *
 * <p>Covers: key generation, signing, verification, size/utility, and conversion functions.
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLLegacyDsa {

    private static final String BUNDLE = "OpenSSL";

    // ====================================================================
    // Signature functions
    // ====================================================================

    private static final IDetectionRule<AstNode> DSA_SIGN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DSA_sign")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DSA-SIGN"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext(SignatureContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DSA_DO_SIGN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DSA_do_sign")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DSA-SIGN"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext(SignatureContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Key Generation
    // ====================================================================

    private static final IDetectionRule<AstNode> DSA_GENERATE_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DSA_generate_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DSA"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DSA_GENERATE_PARAMETERS_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DSA_generate_parameters_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DSA"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLLegacyDsa() {
        // nothing
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(
                // Signatures
                DSA_SIGN,
                DSA_DO_SIGN,
                // Key Generation
                DSA_GENERATE_KEY,
                DSA_GENERATE_PARAMETERS_EX);
    }
}
