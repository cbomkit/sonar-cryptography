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
 * Detection rules for Rust's ring::signature RSA operations.
 *
 * <p>Detects usage of:
 *
 * <ul>
 *   <li>ring::signature::RsaKeyPair::from_pkcs8 - imports an RSA key pair from PKCS#8
 *   <li>ring::signature::RsaKeyPair::from_der - imports an RSA key pair from DER
 *   <li>ring::signature::RsaKeyPair::sign - signs data with an RSA key pair
 *   <li>ring::signature::UnparsedPublicKey::verify - verifies an RSA signature
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class RingRSA {

    private RingRSA() {
        // private
    }

    // ring::signature::RsaKeyPair::from_pkcs8(pkcs8_der: &[u8]) -> Result<Self, KeyRejected>
    // Parses an RSA private key from a PKCS#8 v1 DER-encoded key
    private static final IDetectionRule<Tree> FROM_PKCS8 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("ring::signature::RsaKeyPair")
                    .forMethods("from_pkcs8")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA"))
                    .withMethodParameter("&[u8]")
                    .buildForContext(new KeyContext(Map.of("kind", "RSA")))
                    .inBundle(() -> "RingCrypto")
                    .withoutDependingDetectionRules();

    // ring::signature::RsaKeyPair::from_der(der: &[u8]) -> Result<Self, KeyRejected>
    // Parses an RSA private key from a DER-encoded key
    private static final IDetectionRule<Tree> FROM_DER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("ring::signature::RsaKeyPair")
                    .forMethods("from_der")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA"))
                    .withMethodParameter("&[u8]")
                    .buildForContext(new KeyContext(Map.of("kind", "RSA")))
                    .inBundle(() -> "RingCrypto")
                    .withoutDependingDetectionRules();

    // ring::signature::RsaKeyPair::sign(
    //     &self, padding_alg: &'static dyn RsaEncoding, rng: &dyn SecureRandom, msg: &[u8],
    //     signature: &mut [u8]
    // ) -> Result<(), Unspecified>
    // Signs a message with the RSA key pair
    private static final IDetectionRule<Tree> SIGN =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("ring::signature::RsaKeyPair")
                    .forMethods("sign")
                    .shouldBeDetectedAs(
                            new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withMethodParameter("&dyn RsaEncoding")
                    .withMethodParameter("&dyn SecureRandom")
                    .withMethodParameter("&[u8]")
                    .withMethodParameter("&mut [u8]")
                    .buildForContext(new SignatureContext(Map.of("kind", "RSA")))
                    .inBundle(() -> "RingCrypto")
                    .withoutDependingDetectionRules();

    // ring::signature::UnparsedPublicKey::verify(
    //     &self, message: &[u8], signature: &[u8]
    // ) -> Result<(), Unspecified>
    // Verifies an RSA signature (also used for ECDSA/Ed25519, but type is configured per-rule)
    private static final IDetectionRule<Tree> VERIFY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("ring::signature::UnparsedPublicKey")
                    .forMethods("verify")
                    .shouldBeDetectedAs(
                            new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withMethodParameter("&[u8]")
                    .withMethodParameter("&[u8]")
                    .buildForContext(new SignatureContext(Map.of("kind", "RSA")))
                    .inBundle(() -> "RingCrypto")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(FROM_PKCS8, FROM_DER, SIGN, VERIFY);
    }
}
