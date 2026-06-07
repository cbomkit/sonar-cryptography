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

import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for OpenSSL legacy RSA Direct API functions (from rsa.h).
 *
 * <p>These rules detect RSA operations using the legacy (pre-EVP) APIs. These APIs are deprecated
 * but still widely used in existing codebases.
 *
 * <p>Covers: RSA key management, encryption/decryption, signing/verification, PSS, OAEP
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLLegacyRsa {

    private static final String BUNDLE = "OpenSSL";

    // ====================================================================
    // Signatures
    // ====================================================================

    private static final IDetectionRule<AstNode> RSA_SIGN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RSA_sign")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-SIGN"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext(SignatureContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_VERIFY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RSA_verify")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-VERIFY"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext(SignatureContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // PSS
    // ====================================================================

    private static final IDetectionRule<AstNode> RSA_PADDING_ADD_PKCS1_PSS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RSA_padding_add_PKCS1_PSS")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PSS"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext(SignatureContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_PADDING_ADD_PKCS1_PSS_MGF1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RSA_padding_add_PKCS1_PSS_mgf1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PSS"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext(SignatureContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_VERIFY_PKCS1_PSS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RSA_verify_PKCS1_PSS")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PSS"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext(SignatureContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_VERIFY_PKCS1_PSS_MGF1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RSA_verify_PKCS1_PSS_mgf1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PSS"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext(SignatureContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // PKCS1 type_1 padding (legacy direct)
    // ====================================================================

    private static final IDetectionRule<AstNode> RSA_PADDING_ADD_PKCS1_TYPE_1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RSA_padding_add_PKCS1_type_1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PKCS1"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_PADDING_CHECK_PKCS1_TYPE_1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RSA_padding_check_PKCS1_type_1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PKCS1"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // X9.31 padding
    // ====================================================================

    private static final IDetectionRule<AstNode> RSA_PADDING_ADD_X931 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RSA_padding_add_X931")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-X931"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_PADDING_CHECK_X931 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RSA_padding_check_X931")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-X931"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Key Generation
    // ====================================================================

    private static final IDetectionRule<AstNode> RSA_GENERATE_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RSA_generate_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_GENERATE_KEY_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RSA_generate_key_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_GENERATE_MULTI_PRIME_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RSA_generate_multi_prime_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Encrypt / Decrypt (raw RSA operations)
    // ====================================================================

    private static final IDetectionRule<AstNode> RSA_PUBLIC_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RSA_public_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-ENCRYPT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_PRIVATE_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RSA_private_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-ENCRYPT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_PUBLIC_DECRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RSA_public_decrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-DECRYPT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_PRIVATE_DECRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RSA_private_decrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-DECRYPT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // PKCS1 type_2 padding (encryption padding)
    // ====================================================================

    private static final IDetectionRule<AstNode> RSA_PADDING_ADD_PKCS1_TYPE_2 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RSA_padding_add_PKCS1_type_2")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PKCS1-TYPE2"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_PADDING_CHECK_PKCS1_TYPE_2 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RSA_padding_check_PKCS1_type_2")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PKCS1-TYPE2"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // No-padding (raw RSA)
    // ====================================================================

    private static final IDetectionRule<AstNode> RSA_PADDING_ADD_NONE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RSA_padding_add_none")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-NO-PADDING"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_PADDING_CHECK_NONE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RSA_padding_check_none")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-NO-PADDING"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // OAEP padding (encryption padding)
    // ====================================================================

    private static final IDetectionRule<AstNode> RSA_PADDING_ADD_PKCS1_OAEP =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RSA_padding_add_PKCS1_OAEP")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-OAEP"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_PADDING_CHECK_PKCS1_OAEP =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RSA_padding_check_PKCS1_OAEP")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-OAEP"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_PADDING_ADD_PKCS1_OAEP_MGF1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RSA_padding_add_PKCS1_OAEP_mgf1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-OAEP-MGF1"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_PADDING_CHECK_PKCS1_OAEP_MGF1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RSA_padding_check_PKCS1_OAEP_mgf1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-OAEP-MGF1"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLLegacyRsa() {
        // nothing
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(
                // Signatures
                RSA_SIGN,
                RSA_VERIFY,
                // PSS
                RSA_PADDING_ADD_PKCS1_PSS,
                RSA_PADDING_ADD_PKCS1_PSS_MGF1,
                RSA_VERIFY_PKCS1_PSS,
                RSA_VERIFY_PKCS1_PSS_MGF1,
                // PKCS1 type_1 padding
                RSA_PADDING_ADD_PKCS1_TYPE_1,
                RSA_PADDING_CHECK_PKCS1_TYPE_1,
                // X9.31 padding
                RSA_PADDING_ADD_X931,
                RSA_PADDING_CHECK_X931,
                // Key Generation
                RSA_GENERATE_KEY,
                RSA_GENERATE_KEY_EX,
                RSA_GENERATE_MULTI_PRIME_KEY,
                // Encrypt / Decrypt (raw RSA)
                RSA_PUBLIC_ENCRYPT,
                RSA_PRIVATE_ENCRYPT,
                RSA_PUBLIC_DECRYPT,
                RSA_PRIVATE_DECRYPT,
                // PKCS1 type_2 padding
                RSA_PADDING_ADD_PKCS1_TYPE_2,
                RSA_PADDING_CHECK_PKCS1_TYPE_2,
                // No-padding
                RSA_PADDING_ADD_NONE,
                RSA_PADDING_CHECK_NONE,
                // OAEP padding
                RSA_PADDING_ADD_PKCS1_OAEP,
                RSA_PADDING_CHECK_PKCS1_OAEP,
                RSA_PADDING_ADD_PKCS1_OAEP_MGF1,
                RSA_PADDING_CHECK_PKCS1_OAEP_MGF1);
    }
}
