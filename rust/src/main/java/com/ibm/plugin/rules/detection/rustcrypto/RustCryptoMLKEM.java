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

import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.factory.KeyActionFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.sonar.plugins.go.api.Tree;

/**
 * Detection rules for the RustCrypto ml-kem crate (NIST FIPS 203).
 *
 * <p>Detects usage of quantum-safe ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism):
 *
 * <ul>
 *   <li>ml_kem::MlKem512::generate - generates an ML-KEM-512 key pair
 *   <li>ml_kem::MlKem768::generate - generates an ML-KEM-768 key pair
 *   <li>ml_kem::MlKem1024::generate - generates an ML-KEM-1024 key pair
 *   <li>DecapsulationKey::decapsulate - decapsulates a shared key
 *   <li>EncapsulationKey::encapsulate - encapsulates a shared key
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class RustCryptoMLKEM {

    private RustCryptoMLKEM() {
        // private
    }

    // EncapsulationKey::encapsulate(&self, rng: &mut impl CryptoRngCore)
    //     -> (Ciphertext, SharedKey)
    // Encapsulates a shared key using the encapsulation key (ML-KEM-512)
    private static final IDetectionRule<Tree> ENCAPSULATE_512 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("ml_kem::kem::EncapsulationKey<MlKem512Params>")
                    .forMethods("encapsulate")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.ENCAPSULATION))
                    .withMethodParameter("&mut impl CryptoRngCore")
                    .buildForContext(new KeyContext(Map.of("kind", "KEM")))
                    .inBundle(() -> "RustCrypto")
                    .withoutDependingDetectionRules();

    // EncapsulationKey::encapsulate for ML-KEM-768
    private static final IDetectionRule<Tree> ENCAPSULATE_768 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("ml_kem::kem::EncapsulationKey<MlKem768Params>")
                    .forMethods("encapsulate")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.ENCAPSULATION))
                    .withMethodParameter("&mut impl CryptoRngCore")
                    .buildForContext(new KeyContext(Map.of("kind", "KEM")))
                    .inBundle(() -> "RustCrypto")
                    .withoutDependingDetectionRules();

    // EncapsulationKey::encapsulate for ML-KEM-1024
    private static final IDetectionRule<Tree> ENCAPSULATE_1024 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("ml_kem::kem::EncapsulationKey<MlKem1024Params>")
                    .forMethods("encapsulate")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.ENCAPSULATION))
                    .withMethodParameter("&mut impl CryptoRngCore")
                    .buildForContext(new KeyContext(Map.of("kind", "KEM")))
                    .inBundle(() -> "RustCrypto")
                    .withoutDependingDetectionRules();

    // DecapsulationKey::decapsulate(&self, ciphertext: &Ciphertext) -> SharedKey
    // Decapsulates a shared key from a ciphertext (ML-KEM-512)
    private static final IDetectionRule<Tree> DECAPSULATE_512 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("ml_kem::kem::DecapsulationKey<MlKem512Params>")
                    .forMethods("decapsulate")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.DECAPSULATION))
                    .withMethodParameter("&Ciphertext")
                    .buildForContext(new KeyContext(Map.of("kind", "KEM")))
                    .inBundle(() -> "RustCrypto")
                    .withoutDependingDetectionRules();

    // DecapsulationKey::decapsulate for ML-KEM-768
    private static final IDetectionRule<Tree> DECAPSULATE_768 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("ml_kem::kem::DecapsulationKey<MlKem768Params>")
                    .forMethods("decapsulate")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.DECAPSULATION))
                    .withMethodParameter("&Ciphertext")
                    .buildForContext(new KeyContext(Map.of("kind", "KEM")))
                    .inBundle(() -> "RustCrypto")
                    .withoutDependingDetectionRules();

    // DecapsulationKey::decapsulate for ML-KEM-1024
    private static final IDetectionRule<Tree> DECAPSULATE_1024 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("ml_kem::kem::DecapsulationKey<MlKem1024Params>")
                    .forMethods("decapsulate")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.DECAPSULATION))
                    .withMethodParameter("&Ciphertext")
                    .buildForContext(new KeyContext(Map.of("kind", "KEM")))
                    .inBundle(() -> "RustCrypto")
                    .withoutDependingDetectionRules();

    // ml_kem::MlKem512::generate(rng: &mut impl CryptoRngCore)
    //     -> (DecapsulationKey, EncapsulationKey)
    // Generates an ML-KEM-512 key pair
    private static final IDetectionRule<Tree> GENERATE_512 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("ml_kem::MlKem512")
                    .forMethods("generate")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-KEM-512"))
                    .withMethodParameter("&mut impl CryptoRngCore")
                    .buildForContext(new KeyContext(Map.of("kind", "KEM")))
                    .inBundle(() -> "RustCrypto")
                    .withDependingDetectionRules(
                            List.of(DECAPSULATE_512, ENCAPSULATE_512));

    // ml_kem::MlKem768::generate(rng: &mut impl CryptoRngCore)
    //     -> (DecapsulationKey, EncapsulationKey)
    // Generates an ML-KEM-768 key pair
    private static final IDetectionRule<Tree> GENERATE_768 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("ml_kem::MlKem768")
                    .forMethods("generate")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-KEM-768"))
                    .withMethodParameter("&mut impl CryptoRngCore")
                    .buildForContext(new KeyContext(Map.of("kind", "KEM")))
                    .inBundle(() -> "RustCrypto")
                    .withDependingDetectionRules(
                            List.of(DECAPSULATE_768, ENCAPSULATE_768));

    // ml_kem::MlKem1024::generate(rng: &mut impl CryptoRngCore)
    //     -> (DecapsulationKey, EncapsulationKey)
    // Generates an ML-KEM-1024 key pair
    private static final IDetectionRule<Tree> GENERATE_1024 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("ml_kem::MlKem1024")
                    .forMethods("generate")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-KEM-1024"))
                    .withMethodParameter("&mut impl CryptoRngCore")
                    .buildForContext(new KeyContext(Map.of("kind", "KEM")))
                    .inBundle(() -> "RustCrypto")
                    .withDependingDetectionRules(
                            List.of(DECAPSULATE_1024, ENCAPSULATE_1024));

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(GENERATE_512, GENERATE_768, GENERATE_1024);
    }
}
