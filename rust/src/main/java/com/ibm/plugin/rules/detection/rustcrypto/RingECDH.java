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
import com.ibm.engine.model.context.KeyAgreementContext;
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
 * Detection rules for Rust's ring::agreement ECDH operations.
 *
 * <p>Detects usage of:
 *
 * <ul>
 *   <li>ring::agreement::EphemeralPrivateKey::generate - generates an ephemeral ECDH private key
 *   <li>ring::agreement::agree_ephemeral - performs ECDH key agreement
 *   <li>ring::agreement::UnparsedPublicKey::new - creates a public key for agreement
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class RingECDH {

    private RingECDH() {
        // private
    }

    // ring::agreement::EphemeralPrivateKey::generate(
    //     alg: &'static Algorithm, rng: &dyn SecureRandom
    // ) -> Result<Self, Unspecified>
    // Generates an ephemeral private key for key agreement
    private static final IDetectionRule<Tree> GENERATE =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("ring::agreement::EphemeralPrivateKey")
                    .forMethods("generate")
                    .shouldBeDetectedAs(
                            new KeyActionFactory<>(KeyAction.Action.PRIVATE_KEY_GENERATION))
                    .withMethodParameter("&Algorithm")
                    .withMethodParameter("&dyn SecureRandom")
                    .buildForContext(new KeyContext(Map.of("kind", "ECDH")))
                    .inBundle(() -> "RingCrypto")
                    .withoutDependingDetectionRules();

    // ring::agreement::agree_ephemeral(
    //     my_private_key: EphemeralPrivateKey, peer_public_key: &UnparsedPublicKey<B>,
    //     kdf: impl FnOnce(&[u8]) -> Result<R, E>
    // ) -> Result<R, E>
    // Performs ECDH key agreement between an ephemeral private key and a peer's public key
    private static final IDetectionRule<Tree> AGREE_EPHEMERAL =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("ring::agreement")
                    .forMethods("agree_ephemeral")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDH"))
                    .withMethodParameter("EphemeralPrivateKey")
                    .addDependingDetectionRules(List.of(GENERATE))
                    .withMethodParameter("&UnparsedPublicKey")
                    .withMethodParameter("FnOnce")
                    .buildForContext(new KeyAgreementContext(Map.of("kind", "ECDH")))
                    .inBundle(() -> "RingCrypto")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(GENERATE, AGREE_EPHEMERAL);
    }
}
