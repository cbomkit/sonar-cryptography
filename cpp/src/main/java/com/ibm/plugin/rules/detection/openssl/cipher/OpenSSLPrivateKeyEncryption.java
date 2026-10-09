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
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/**
 * Detection rules for the encryption of a private key when it is written: {@code
 * PEM_write_bio_PrivateKey} and the other PEM, PKCS#8 and DER writers encrypt the key with the
 * cipher given to them ({@code enc}) under a key derived from a password. A key written without a
 * cipher is not encrypted, and not reported.
 */
public final class OpenSSLPrivateKeyEncryption extends DetectionRuleSet<AstNode> {

    private static final String BUNDLE = "OpenSSL";

    /** The writers taking (out, pkey, enc, kstr, klen, cb, u). */
    private static final List<String> WRITERS =
            List.of(
                    "PEM_write_bio_PrivateKey",
                    "PEM_write_PrivateKey",
                    "PEM_write_bio_PrivateKey_traditional",
                    "PEM_write_bio_PKCS8PrivateKey",
                    "PEM_write_PKCS8PrivateKey",
                    "i2d_PKCS8PrivateKey_bio",
                    "i2d_PKCS8PrivateKey_fp");

    /** The writers taking (out, pkey, enc, kstr, klen, cb, u, libctx, propq). */
    private static final List<String> WRITERS_EX = List.of("PEM_write_bio_PrivateKey_ex");

    private static final IDetectionRule<AstNode> WRITE_ENCRYPTED = writer(WRITERS, 7);

    private static final IDetectionRule<AstNode> WRITE_ENCRYPTED_EX = writer(WRITERS_EX, 9);

    /** A writer whose third argument, {@code enc}, is the cipher that encrypts the key. */
    @Nonnull
    private static IDetectionRule<AstNode> writer(
            @Nonnull List<String> functions, int parameterCount) {
        IDetectionRule.ParametersFactoryBuilder<AstNode> parameters =
                new DetectionRuleBuilder<AstNode>()
                        .createDetectionRule()
                        .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                        .forMethods(functions.toArray(new String[0]))
                        .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                        .withMethodParameter("*")
                        .withMethodParameter("*")
                        .withMethodParameter("*")
                        .addDependingDetectionRules(
                                RuleSets.rulesOf(OpenSSLEvpCipher.CipherSelection.class))
                        .withMethodParameter("*");
        for (int i = 4; i < parameterCount; i++) {
            parameters = parameters.withMethodParameter("*");
        }
        return parameters
                .buildForContext(new CipherContext())
                .inBundle(() -> BUNDLE)
                .withoutDependingDetectionRules();
    }

    @Nonnull
    @Override
    protected List<IDetectionRule<AstNode>> buildRules() {
        return Stream.of(WRITE_ENCRYPTED, WRITE_ENCRYPTED_EX).toList();
    }
}
