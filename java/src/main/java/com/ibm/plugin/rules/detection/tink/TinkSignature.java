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
package com.ibm.plugin.rules.detection.tink;

import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

/**
 * Detection rules for Google Tink digital signature primitive.
 *
 * <ul>
 *   <li>{@code KeysetHandle.generateNew(SignatureKeyTemplates.ECDSA_P256)}
 *   <li>{@code KeysetHandle.generateNew(SignatureKeyTemplates.ED25519)}
 *   <li>{@code signer.sign(data)}
 *   <li>{@code verifier.verify(signature, data)}
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class TinkSignature {

    private TinkSignature() {
        // nothing
    }

    // signer.sign(byte[] data)
    private static final IDetectionRule<Tree> SIGN =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("com.google.crypto.tink.PublicKeySign")
                    .forMethods("sign")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SIGN"))
                    .withMethodParameter(MethodMatcher.ANY)
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "Tink")
                    .withoutDependingDetectionRules();

    // verifier.verify(byte[] signature, byte[] data)
    private static final IDetectionRule<Tree> VERIFY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("com.google.crypto.tink.PublicKeyVerify")
                    .forMethods("verify")
                    .shouldBeDetectedAs(new ValueActionFactory<>("VERIFY"))
                    .withMethodParameter(MethodMatcher.ANY)
                    .withMethodParameter(MethodMatcher.ANY)
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "Tink")
                    .withoutDependingDetectionRules();

    private static final List<IDetectionRule<Tree>> SIGN_OP_RULES = List.of(SIGN, VERIFY);

    private static IDetectionRule<Tree> signKeyRule(String value) {
        return new DetectionRuleBuilder<Tree>()
                .createDetectionRule()
                .forObjectTypes("com.google.crypto.tink.KeysetHandle")
                .forMethods("generateNew")
                .shouldBeDetectedAs(new ValueActionFactory<>(value))
                .withAnyParameters()
                .buildForContext(new SignatureContext())
                .inBundle(() -> "Tink")
                .withDependingDetectionRules(SIGN_OP_RULES);
    }

    private static final IDetectionRule<Tree> ECDSA_P256 = signKeyRule("ECDSA_P256");
    private static final IDetectionRule<Tree> ECDSA_P384 = signKeyRule("ECDSA_P384");
    private static final IDetectionRule<Tree> ECDSA_P521 = signKeyRule("ECDSA_P521");
    private static final IDetectionRule<Tree> ED25519 = signKeyRule("ED25519");
    private static final IDetectionRule<Tree> RSA_SSA_PKCS1_3072_SHA256_F4 =
            signKeyRule("RSA_SSA_PKCS1_3072_SHA256_F4");

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(ECDSA_P256, ECDSA_P384, ECDSA_P521, ED25519, RSA_SSA_PKCS1_3072_SHA256_F4);
    }
}
