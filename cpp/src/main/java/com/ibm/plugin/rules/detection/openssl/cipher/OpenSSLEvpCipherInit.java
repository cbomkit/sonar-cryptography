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
package com.ibm.plugin.rules.detection.openssl.cipher;

import com.ibm.engine.language.cxx.CxxLanguageTranslation;
import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.CipherActionFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.RuleSets;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for the initialization of an OpenSSL cipher context: {@code EVP_EncryptInit},
 * {@code EVP_DecryptInit} and {@code EVP_CipherInit} with their {@code _ex} / {@code _ex2}
 * variants, and the envelope encryption and decryption {@code EVP_SealInit} / {@code EVP_OpenInit}
 * (whose session key is encrypted with the keys given to them, see {@code OpenSSLEvpKeyUsage}). The
 * cipher argument is traced back to the call that selects it. These are the depending rules of the
 * creation of the context ({@link OpenSSLEvpCipherContext}), as the JCA {@code Cipher.init} rules
 * are depending rules of {@code Cipher.getInstance}. A context is often created by the caller of
 * the function that initializes it, so they are detection rules on their own as well; an
 * initialization reported with the creation of its context is not reported again.
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLEvpCipherInit extends DetectionRuleSet<AstNode> {

    private static final String BUNDLE = "OpenSSL";

    // Cipher initialization: (ctx, cipher, ...) for encryption or decryption

    private static final IDetectionRule<AstNode> EVP_ENCRYPT_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_EncryptInit")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(
                            RuleSets.rulesOf(OpenSSLEvpCipher.CipherSelection.class))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_ENCRYPT_INIT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_EncryptInit_ex", "EVP_EncryptInit_ex2")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(
                            RuleSets.rulesOf(OpenSSLEvpCipher.CipherSelection.class))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DECRYPT_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_DecryptInit")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.DECRYPT))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(
                            RuleSets.rulesOf(OpenSSLEvpCipher.CipherSelection.class))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DECRYPT_INIT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_DecryptInit_ex", "EVP_DecryptInit_ex2")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.DECRYPT))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(
                            RuleSets.rulesOf(OpenSSLEvpCipher.CipherSelection.class))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // EVP_CipherInit: the operation is given by the enc argument (1 encrypts, 0 decrypts)

    private static final IDetectionRule<AstNode> EVP_CIPHER_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_CipherInit")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(
                            RuleSets.rulesOf(OpenSSLEvpCipher.CipherSelection.class))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new OpenSSLCipherOperationFactory())
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_CIPHER_INIT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_CipherInit_ex")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(
                            RuleSets.rulesOf(OpenSSLEvpCipher.CipherSelection.class))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new OpenSSLCipherOperationFactory())
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_CIPHER_INIT_EX2 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_CipherInit_ex2")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(
                            RuleSets.rulesOf(OpenSSLEvpCipher.CipherSelection.class))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new OpenSSLCipherOperationFactory())
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // Envelope encryption: EVP_SealInit(ctx, type, ek, ekl, iv, pubk, npubk) encrypts with a random
    // session key, EVP_OpenInit(ctx, type, ek, ekl, iv, priv) decrypts

    private static final IDetectionRule<AstNode> EVP_SEAL_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_SealInit")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(
                            RuleSets.rulesOf(OpenSSLEvpCipher.CipherSelection.class))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_OPEN_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_OpenInit")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.DECRYPT))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(
                            RuleSets.rulesOf(OpenSSLEvpCipher.CipherSelection.class))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<AstNode>> buildRules() {
        return List.of(
                EVP_ENCRYPT_INIT,
                EVP_ENCRYPT_INIT_EX,
                EVP_DECRYPT_INIT,
                EVP_DECRYPT_INIT_EX,
                EVP_CIPHER_INIT,
                EVP_CIPHER_INIT_EX,
                EVP_CIPHER_INIT_EX2,
                EVP_SEAL_INIT,
                EVP_OPEN_INIT);
    }
}
