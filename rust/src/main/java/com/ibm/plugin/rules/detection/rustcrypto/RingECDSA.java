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
package com.ibm.plugin.rules.detection.rustcrypto;

import com.ibm.engine.model.SignatureAction;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.SignatureActionFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.sonar.plugins.go.api.Tree;

/**
 * Detection rules for Rust's ring::signature ECDSA operations.
 *
 * <p>Detects usage of:
 *
 * <ul>
 *   <li>ring::signature::EcdsaKeyPair::from_pkcs8 - imports an ECDSA key pair from PKCS#8
 *   <li>ring::signature::EcdsaKeyPair::from_private_key_and_public_key - imports ECDSA key
 *       components
 *   <li>ring::signature::EcdsaKeyPair::sign - signs data with an ECDSA key pair
 *   <li>ring::signature::UnparsedPublicKey::verify - verifies an ECDSA signature
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class RingECDSA {

    private RingECDSA() {
        // private
    }

    // ring::signature::EcdsaKeyPair::from_pkcs8(
    //     alg: &'static EcdsaSigningAlgorithm, pkcs8: &[u8], rng: &dyn SecureRandom
    // ) -> Result<Self, KeyRejected>
    // Parses an ECDSA private key from a PKCS#8 v1 DER-encoded key
    private static final IDetectionRule<Tree> FROM_PKCS8 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("ring::signature::EcdsaKeyPair")
                    .forMethods("from_pkcs8")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDSA"))
                    .withMethodParameter("&EcdsaSigningAlgorithm")
                    .withMethodParameter("&[u8]")
                    .withMethodParameter("&dyn SecureRandom")
                    .buildForContext(new KeyContext(Map.of("kind", "ECDSA")))
                    .inBundle(() -> "RingCrypto")
                    .withoutDependingDetectionRules();

    // ring::signature::EcdsaKeyPair::from_private_key_and_public_key(
    //     alg: &'static EcdsaSigningAlgorithm, private_key: &[u8], public_key: &[u8],
    //     rng: &dyn SecureRandom
    // ) -> Result<Self, KeyRejected>
    // Creates an ECDSA key pair from separate private and public key bytes
    private static final IDetectionRule<Tree> FROM_PRIVATE_KEY_AND_PUBLIC_KEY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("ring::signature::EcdsaKeyPair")
                    .forMethods("from_private_key_and_public_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDSA"))
                    .withMethodParameter("&EcdsaSigningAlgorithm")
                    .withMethodParameter("&[u8]")
                    .withMethodParameter("&[u8]")
                    .withMethodParameter("&dyn SecureRandom")
                    .buildForContext(new KeyContext(Map.of("kind", "ECDSA")))
                    .inBundle(() -> "RingCrypto")
                    .withoutDependingDetectionRules();

    // ring::signature::EcdsaKeyPair::sign(
    //     &self, rng: &dyn SecureRandom, msg: &[u8]
    // ) -> Result<Signature, Unspecified>
    // Signs a message with the ECDSA key pair
    private static final IDetectionRule<Tree> SIGN =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("ring::signature::EcdsaKeyPair")
                    .forMethods("sign")
                    .shouldBeDetectedAs(
                            new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withMethodParameter("&dyn SecureRandom")
                    .withMethodParameter("&[u8]")
                    .buildForContext(new SignatureContext(Map.of("kind", "ECDSA")))
                    .inBundle(() -> "RingCrypto")
                    .withoutDependingDetectionRules();

    // ring::signature::UnparsedPublicKey::verify for ECDSA
    private static final IDetectionRule<Tree> VERIFY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("ring::signature::UnparsedPublicKey")
                    .forMethods("verify")
                    .shouldBeDetectedAs(
                            new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withMethodParameter("&[u8]")
                    .withMethodParameter("&[u8]")
                    .buildForContext(new SignatureContext(Map.of("kind", "ECDSA")))
                    .inBundle(() -> "RingCrypto")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(FROM_PKCS8, FROM_PRIVATE_KEY_AND_PUBLIC_KEY, SIGN, VERIFY);
    }
}
