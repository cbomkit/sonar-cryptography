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
import java.util.Map;
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

    /**
     * int RSA_sign/RSA_verify(int type, ...) - {@code type} is a real NID (obj_mac.h) identifying
     * the digest the signature was computed/verified over, not a placeholder; resolved via {@link
     * OpenSSLNidLookupFactory} the same way curve/DH-group/protocol-version NIDs are elsewhere.
     */
    private static final Map<Integer, String> RSA_SIGN_DIGEST_BY_CODE =
            Map.ofEntries(
                    Map.entry(64, "RSA-SIGN-SHA1"), // NID_sha1
                    Map.entry(675, "RSA-SIGN-SHA224"), // NID_sha224
                    Map.entry(672, "RSA-SIGN-SHA256"), // NID_sha256
                    Map.entry(673, "RSA-SIGN-SHA384"), // NID_sha384
                    Map.entry(674, "RSA-SIGN-SHA512"), // NID_sha512
                    Map.entry(4, "RSA-SIGN-MD5"), // NID_md5
                    Map.entry(114, "RSA-SIGN-MD5-SHA1")); // NID_md5_sha1

    private static final Map<String, String> RSA_SIGN_DIGEST_BY_NAME =
            Map.ofEntries(
                    Map.entry("NID_sha1", "RSA-SIGN-SHA1"),
                    Map.entry("NID_sha224", "RSA-SIGN-SHA224"),
                    Map.entry("NID_sha256", "RSA-SIGN-SHA256"),
                    Map.entry("NID_sha384", "RSA-SIGN-SHA384"),
                    Map.entry("NID_sha512", "RSA-SIGN-SHA512"),
                    Map.entry("NID_md5", "RSA-SIGN-MD5"),
                    Map.entry("NID_md5_sha1", "RSA-SIGN-MD5-SHA1"));

    private static final Map<Integer, String> RSA_VERIFY_DIGEST_BY_CODE =
            Map.ofEntries(
                    Map.entry(64, "RSA-VERIFY-SHA1"),
                    Map.entry(675, "RSA-VERIFY-SHA224"),
                    Map.entry(672, "RSA-VERIFY-SHA256"),
                    Map.entry(673, "RSA-VERIFY-SHA384"),
                    Map.entry(674, "RSA-VERIFY-SHA512"),
                    Map.entry(4, "RSA-VERIFY-MD5"),
                    Map.entry(114, "RSA-VERIFY-MD5-SHA1"));

    private static final Map<String, String> RSA_VERIFY_DIGEST_BY_NAME =
            Map.ofEntries(
                    Map.entry("NID_sha1", "RSA-VERIFY-SHA1"),
                    Map.entry("NID_sha224", "RSA-VERIFY-SHA224"),
                    Map.entry("NID_sha256", "RSA-VERIFY-SHA256"),
                    Map.entry("NID_sha384", "RSA-VERIFY-SHA384"),
                    Map.entry("NID_sha512", "RSA-VERIFY-SHA512"),
                    Map.entry("NID_md5", "RSA-VERIFY-MD5"),
                    Map.entry("NID_md5_sha1", "RSA-VERIFY-MD5-SHA1"));

    private static final IDetectionRule<AstNode> RSA_SIGN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RSA_sign")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNidLookupFactory(
                                    RSA_SIGN_DIGEST_BY_CODE, RSA_SIGN_DIGEST_BY_NAME))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_VERIFY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RSA_verify")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNidLookupFactory(
                                    RSA_VERIFY_DIGEST_BY_CODE, RSA_VERIFY_DIGEST_BY_NAME))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new SignatureContext())
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
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_PADDING_ADD_PKCS1_PSS_MGF1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RSA_padding_add_PKCS1_PSS_mgf1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PSS"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_VERIFY_PKCS1_PSS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RSA_verify_PKCS1_PSS")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PSS"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_VERIFY_PKCS1_PSS_MGF1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RSA_verify_PKCS1_PSS_mgf1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PSS"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
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
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_GENERATE_KEY_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RSA_generate_key_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_GENERATE_MULTI_PRIME_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RSA_generate_multi_prime_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
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
