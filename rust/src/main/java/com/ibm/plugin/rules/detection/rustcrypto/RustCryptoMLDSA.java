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
 * Detection rules for the RustCrypto ml-dsa crate (NIST FIPS 204).
 *
 * <p>Detects usage of quantum-safe ML-DSA (Module-Lattice-Based Digital Signature Algorithm):
 *
 * <ul>
 *   <li>ml_dsa::MlDsa44::key_gen - generates an ML-DSA-44 key pair
 *   <li>ml_dsa::MlDsa65::key_gen - generates an ML-DSA-65 key pair
 *   <li>ml_dsa::MlDsa87::key_gen - generates an ML-DSA-87 key pair
 *   <li>SigningKey::sign - signs a message
 *   <li>VerifyingKey::verify - verifies a signature
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class RustCryptoMLDSA {

    private RustCryptoMLDSA() {
        // private
    }

    // SigningKey<MlDsa44>::sign(&self, rng: &mut impl CryptoRngCore, msg: &[u8]) -> Signature
    // Signs a message using the ML-DSA-44 signing key
    private static final IDetectionRule<Tree> SIGN_44 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("ml_dsa::SigningKey<MlDsa44>")
                    .forMethods("sign")
                    .shouldBeDetectedAs(
                            new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withMethodParameter("&mut impl CryptoRngCore")
                    .withMethodParameter("&[u8]")
                    .buildForContext(new SignatureContext(Map.of("kind", "ML-DSA")))
                    .inBundle(() -> "RustCrypto")
                    .withoutDependingDetectionRules();

    // SigningKey<MlDsa65>::sign
    private static final IDetectionRule<Tree> SIGN_65 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("ml_dsa::SigningKey<MlDsa65>")
                    .forMethods("sign")
                    .shouldBeDetectedAs(
                            new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withMethodParameter("&mut impl CryptoRngCore")
                    .withMethodParameter("&[u8]")
                    .buildForContext(new SignatureContext(Map.of("kind", "ML-DSA")))
                    .inBundle(() -> "RustCrypto")
                    .withoutDependingDetectionRules();

    // SigningKey<MlDsa87>::sign
    private static final IDetectionRule<Tree> SIGN_87 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("ml_dsa::SigningKey<MlDsa87>")
                    .forMethods("sign")
                    .shouldBeDetectedAs(
                            new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withMethodParameter("&mut impl CryptoRngCore")
                    .withMethodParameter("&[u8]")
                    .buildForContext(new SignatureContext(Map.of("kind", "ML-DSA")))
                    .inBundle(() -> "RustCrypto")
                    .withoutDependingDetectionRules();

    // VerifyingKey<MlDsa44>::verify(&self, msg: &[u8], signature: &Signature) -> Result<()>
    // Verifies a signature using the ML-DSA-44 verifying key
    private static final IDetectionRule<Tree> VERIFY_44 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("ml_dsa::VerifyingKey<MlDsa44>")
                    .forMethods("verify")
                    .shouldBeDetectedAs(
                            new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withMethodParameter("&[u8]")
                    .withMethodParameter("&Signature")
                    .buildForContext(new SignatureContext(Map.of("kind", "ML-DSA")))
                    .inBundle(() -> "RustCrypto")
                    .withoutDependingDetectionRules();

    // VerifyingKey<MlDsa65>::verify
    private static final IDetectionRule<Tree> VERIFY_65 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("ml_dsa::VerifyingKey<MlDsa65>")
                    .forMethods("verify")
                    .shouldBeDetectedAs(
                            new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withMethodParameter("&[u8]")
                    .withMethodParameter("&Signature")
                    .buildForContext(new SignatureContext(Map.of("kind", "ML-DSA")))
                    .inBundle(() -> "RustCrypto")
                    .withoutDependingDetectionRules();

    // VerifyingKey<MlDsa87>::verify
    private static final IDetectionRule<Tree> VERIFY_87 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("ml_dsa::VerifyingKey<MlDsa87>")
                    .forMethods("verify")
                    .shouldBeDetectedAs(
                            new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withMethodParameter("&[u8]")
                    .withMethodParameter("&Signature")
                    .buildForContext(new SignatureContext(Map.of("kind", "ML-DSA")))
                    .inBundle(() -> "RustCrypto")
                    .withoutDependingDetectionRules();

    // ml_dsa::MlDsa44::key_gen(rng: &mut impl CryptoRngCore) -> (SigningKey, VerifyingKey)
    // Generates an ML-DSA-44 key pair
    private static final IDetectionRule<Tree> KEY_GEN_44 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("ml_dsa::MlDsa44")
                    .forMethods("key_gen")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-DSA-44"))
                    .withMethodParameter("&mut impl CryptoRngCore")
                    .buildForContext(new KeyContext(Map.of("kind", "ML-DSA")))
                    .inBundle(() -> "RustCrypto")
                    .withDependingDetectionRules(List.of(SIGN_44, VERIFY_44));

    // ml_dsa::MlDsa65::key_gen(rng: &mut impl CryptoRngCore) -> (SigningKey, VerifyingKey)
    // Generates an ML-DSA-65 key pair
    private static final IDetectionRule<Tree> KEY_GEN_65 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("ml_dsa::MlDsa65")
                    .forMethods("key_gen")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-DSA-65"))
                    .withMethodParameter("&mut impl CryptoRngCore")
                    .buildForContext(new KeyContext(Map.of("kind", "ML-DSA")))
                    .inBundle(() -> "RustCrypto")
                    .withDependingDetectionRules(List.of(SIGN_65, VERIFY_65));

    // ml_dsa::MlDsa87::key_gen(rng: &mut impl CryptoRngCore) -> (SigningKey, VerifyingKey)
    // Generates an ML-DSA-87 key pair
    private static final IDetectionRule<Tree> KEY_GEN_87 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("ml_dsa::MlDsa87")
                    .forMethods("key_gen")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-DSA-87"))
                    .withMethodParameter("&mut impl CryptoRngCore")
                    .buildForContext(new KeyContext(Map.of("kind", "ML-DSA")))
                    .inBundle(() -> "RustCrypto")
                    .withDependingDetectionRules(List.of(SIGN_87, VERIFY_87));

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(KEY_GEN_44, KEY_GEN_65, KEY_GEN_87);
    }
}
