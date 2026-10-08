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

import com.ibm.engine.language.cxx.CxxLanguageTranslation;
import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.SignatureAction;
import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.CipherActionFactory;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.model.factory.SignatureActionFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.RuleSets;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.openssl.OpenSSLSizeFactory;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLEvpMessageDigest;
import com.ibm.plugin.rules.detection.openssl.signature.OpenSSLSaltLengthFactory;
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
public final class OpenSSLLegacyRsa extends DetectionRuleSet<AstNode> {

    private static final String BUNDLE = "OpenSSL";

    // Signatures

    /**
     * int RSA_sign/RSA_verify(int type, ...): {@code type} is the NID (obj_mac.h) of the digest the
     * signature is computed or verified over, resolved via {@link OpenSSLNidLookupFactory} to the
     * name of the signature scheme with that digest (e.g. {@code RSA-SHA256}).
     */
    private static final Map<Integer, String> RSA_DIGEST_BY_CODE =
            Map.ofEntries(
                    Map.entry(64, "RSA-SHA1"), // NID_sha1
                    Map.entry(675, "RSA-SHA224"), // NID_sha224
                    Map.entry(672, "RSA-SHA256"), // NID_sha256
                    Map.entry(673, "RSA-SHA384"), // NID_sha384
                    Map.entry(674, "RSA-SHA512"), // NID_sha512
                    Map.entry(4, "RSA-MD5"), // NID_md5
                    Map.entry(114, "RSA-MD5-SHA1")); // NID_md5_sha1

    private static final Map<String, String> RSA_DIGEST_BY_NAME =
            Map.ofEntries(
                    Map.entry("NID_sha1", "RSA-SHA1"),
                    Map.entry("NID_sha224", "RSA-SHA224"),
                    Map.entry("NID_sha256", "RSA-SHA256"),
                    Map.entry("NID_sha384", "RSA-SHA384"),
                    Map.entry("NID_sha512", "RSA-SHA512"),
                    Map.entry("NID_md5", "RSA-MD5"),
                    Map.entry("NID_md5_sha1", "RSA-MD5-SHA1"));

    private static final IDetectionRule<AstNode> RSA_SIGN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("RSA_sign")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNidLookupFactory(RSA_DIGEST_BY_CODE, RSA_DIGEST_BY_NAME))
                    .asChildOfParameterWithId(-1)
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
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("RSA_verify")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNidLookupFactory(RSA_DIGEST_BY_CODE, RSA_DIGEST_BY_NAME))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // PSS

    private static final IDetectionRule<AstNode> RSA_PADDING_ADD_PKCS1_PSS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("RSA_padding_add_PKCS1_PSS")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PSS"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(RuleSets.rulesOf(OpenSSLEvpMessageDigest.class))
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new OpenSSLSaltLengthFactory())
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_PADDING_ADD_PKCS1_PSS_MGF1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("RSA_padding_add_PKCS1_PSS_mgf1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PSS"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(RuleSets.rulesOf(OpenSSLEvpMessageDigest.class))
                    .withMethodParameter("*")
                    .addDependingDetectionRules(
                            RuleSets.rulesOf(OpenSSLEvpMessageDigest.Mgf1.class))
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new OpenSSLSaltLengthFactory())
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_VERIFY_PKCS1_PSS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("RSA_verify_PKCS1_PSS")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PSS"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(RuleSets.rulesOf(OpenSSLEvpMessageDigest.class))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new OpenSSLSaltLengthFactory())
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_VERIFY_PKCS1_PSS_MGF1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("RSA_verify_PKCS1_PSS_mgf1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PSS"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(RuleSets.rulesOf(OpenSSLEvpMessageDigest.class))
                    .withMethodParameter("*")
                    .addDependingDetectionRules(
                            RuleSets.rulesOf(OpenSSLEvpMessageDigest.Mgf1.class))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new OpenSSLSaltLengthFactory())
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // PKCS1 type_1 padding (legacy direct)

    private static final IDetectionRule<AstNode> RSA_PADDING_ADD_PKCS1_TYPE_1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("RSA_padding_add_PKCS1_type_1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PKCS1"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_PADDING_CHECK_PKCS1_TYPE_1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("RSA_padding_check_PKCS1_type_1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PKCS1"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // X9.31 padding

    private static final IDetectionRule<AstNode> RSA_PADDING_ADD_X931 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("RSA_padding_add_X931")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-X931"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_PADDING_CHECK_X931 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("RSA_padding_check_X931")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-X931"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // Raw RSA operations: RSA_*_encrypt / RSA_*_decrypt(flen, from, to, rsa, padding). The
    // public-key encryption and private-key decryption use an encryption scheme; the private-key
    // "encryption" and public-key "decryption" are the signature primitive and its verification.

    private static final IDetectionRule<AstNode> RSA_PUBLIC_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("RSA_public_encrypt")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNidLookupFactory(
                                    OpenSSLNidLookupFactory.RSA_ENCRYPTION_PADDING_BY_CODE,
                                    OpenSSLNidLookupFactory.RSA_ENCRYPTION_PADDING_BY_NAME))
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_PRIVATE_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("RSA_private_encrypt")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNidLookupFactory(
                                    OpenSSLNidLookupFactory.RSA_SIGNATURE_PADDING_BY_CODE,
                                    OpenSSLNidLookupFactory.RSA_SIGNATURE_PADDING_BY_NAME))
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_PUBLIC_DECRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("RSA_public_decrypt")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNidLookupFactory(
                                    OpenSSLNidLookupFactory.RSA_SIGNATURE_PADDING_BY_CODE,
                                    OpenSSLNidLookupFactory.RSA_SIGNATURE_PADDING_BY_NAME))
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_PRIVATE_DECRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("RSA_private_decrypt")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.DECRYPT))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNidLookupFactory(
                                    OpenSSLNidLookupFactory.RSA_ENCRYPTION_PADDING_BY_CODE,
                                    OpenSSLNidLookupFactory.RSA_ENCRYPTION_PADDING_BY_NAME))
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // PKCS1 type_2 padding (encryption padding)

    private static final IDetectionRule<AstNode> RSA_PADDING_ADD_PKCS1_TYPE_2 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("RSA_padding_add_PKCS1_type_2")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PKCS1-TYPE2"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_PADDING_CHECK_PKCS1_TYPE_2 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("RSA_padding_check_PKCS1_type_2")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PKCS1-TYPE2"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // No-padding (raw RSA)

    private static final IDetectionRule<AstNode> RSA_PADDING_ADD_NONE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("RSA_padding_add_none")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-NO-PADDING"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_PADDING_CHECK_NONE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("RSA_padding_check_none")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-NO-PADDING"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // OAEP padding (encryption padding)

    private static final IDetectionRule<AstNode> RSA_PADDING_ADD_PKCS1_OAEP =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("RSA_padding_add_PKCS1_OAEP")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-OAEP"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_PADDING_CHECK_PKCS1_OAEP =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("RSA_padding_check_PKCS1_OAEP")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-OAEP"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_PADDING_ADD_PKCS1_OAEP_MGF1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("RSA_padding_add_PKCS1_OAEP_mgf1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-OAEP-MGF1"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(
                            RuleSets.rulesOf(OpenSSLEvpMessageDigest.Oaep.class))
                    .withMethodParameter("*")
                    .addDependingDetectionRules(
                            RuleSets.rulesOf(OpenSSLEvpMessageDigest.Mgf1.class))
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_PADDING_CHECK_PKCS1_OAEP_MGF1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("RSA_padding_check_PKCS1_OAEP_mgf1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-OAEP-MGF1"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(
                            RuleSets.rulesOf(OpenSSLEvpMessageDigest.Oaep.class))
                    .withMethodParameter("*")
                    .addDependingDetectionRules(
                            RuleSets.rulesOf(OpenSSLEvpMessageDigest.Mgf1.class))
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // The operations made with a generated key, given as an argument of each of them: the
    // signatures, the PSS encodings, and the raw RSA operations
    private static final List<IDetectionRule<AstNode>> KEY_OPERATIONS =
            List.of(
                    RSA_SIGN,
                    RSA_VERIFY,
                    RSA_PADDING_ADD_PKCS1_PSS,
                    RSA_PADDING_ADD_PKCS1_PSS_MGF1,
                    RSA_VERIFY_PKCS1_PSS,
                    RSA_VERIFY_PKCS1_PSS_MGF1,
                    RSA_PUBLIC_ENCRYPT,
                    RSA_PRIVATE_ENCRYPT,
                    RSA_PUBLIC_DECRYPT,
                    RSA_PRIVATE_DECRYPT);

    // Key Generation, followed by the operations made with the key

    private static final IDetectionRule<AstNode> RSA_GENERATE_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("RSA_generate_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA"))
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLSizeFactory(new KeySizeFactory<>(Size.UnitType.BIT)))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new PrivateKeyContext(Map.of()))
                    .inBundle(() -> BUNDLE)
                    .withDependingDetectionRules(KEY_OPERATIONS);

    private static final IDetectionRule<AstNode> RSA_GENERATE_KEY_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("RSA_generate_key_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLSizeFactory(new KeySizeFactory<>(Size.UnitType.BIT)))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new PrivateKeyContext(Map.of()))
                    .inBundle(() -> BUNDLE)
                    .withDependingDetectionRules(KEY_OPERATIONS);

    private static final IDetectionRule<AstNode> RSA_GENERATE_MULTI_PRIME_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("RSA_generate_multi_prime_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLSizeFactory(new KeySizeFactory<>(Size.UnitType.BIT)))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new PrivateKeyContext(Map.of()))
                    .inBundle(() -> BUNDLE)
                    .withDependingDetectionRules(KEY_OPERATIONS);

    @Nonnull
    @Override
    protected List<IDetectionRule<AstNode>> buildRules() {
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
