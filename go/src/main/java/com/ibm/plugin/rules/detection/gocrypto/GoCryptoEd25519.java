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
package com.ibm.plugin.rules.detection.gocrypto;

import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.sonar.plugins.go.api.Tree;

/**
 * Detection rules for Go's crypto/ed25519 package.
 *
 * <p>Detects usage of:
 *
 * <ul>
 *   <li>ed25519.GenerateKey(rand) - generates an Ed25519 keypair
 *   <li>ed25519.NewKeyFromSeed(seed) - creates a private key from seed
 *   <li>ed25519.Sign(priv, message) - signs a message
 *   <li>ed25519.Verify(pub, message, sig) - verifies a signature
 *   <li>ed25519.VerifyWithOptions(pub, message, sig, opts) - verifies with options
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class GoCryptoEd25519 {

    private GoCryptoEd25519() {
        // private
    }

    // ed25519.GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error)
    // Generates a public/private key pair using entropy from rand
    private static final IDetectionRule<Tree> GENERATE_KEY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/ed25519")
                    .forMethods("GenerateKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("Ed25519"))
                    .withMethodParameter("*")
                    .buildForContext(new KeyContext(Map.of("kind", "Ed25519")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // ed25519.NewKeyFromSeed(seed []byte) PrivateKey
    // Calculates a private key from a seed
    private static final IDetectionRule<Tree> NEW_KEY_FROM_SEED =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/ed25519")
                    .forMethods("NewKeyFromSeed")
                    .shouldBeDetectedAs(new ValueActionFactory<>("Ed25519"))
                    .withMethodParameter("*")
                    .buildForContext(new KeyContext(Map.of("kind", "Ed25519")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // ed25519.Sign(privateKey PrivateKey, message []byte) []byte
    // Signs the message with privateKey
    private static final IDetectionRule<Tree> SIGN =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/ed25519")
                    .forMethods("Sign")
                    .shouldBeDetectedAs(new ValueActionFactory<>("Ed25519"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new SignatureContext(Map.of("kind", "Ed25519")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // ed25519.Verify(publicKey PublicKey, message, sig []byte) bool
    // Reports whether sig is a valid signature of message by publicKey
    private static final IDetectionRule<Tree> VERIFY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/ed25519")
                    .forMethods("Verify")
                    .shouldBeDetectedAs(new ValueActionFactory<>("Ed25519"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new SignatureContext(Map.of("kind", "Ed25519")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // ed25519.VerifyWithOptions(publicKey PublicKey, message, sig []byte, opts *Options) error
    // Verifies signature with options (Ed25519ph, Ed25519ctx variants)
    private static final IDetectionRule<Tree> VERIFY_WITH_OPTIONS =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/ed25519")
                    .forMethods("VerifyWithOptions")
                    .shouldBeDetectedAs(new ValueActionFactory<>("Ed25519"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new SignatureContext(Map.of("kind", "Ed25519")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(GENERATE_KEY, NEW_KEY_FROM_SEED, SIGN, VERIFY, VERIFY_WITH_OPTIONS);
    }
}
