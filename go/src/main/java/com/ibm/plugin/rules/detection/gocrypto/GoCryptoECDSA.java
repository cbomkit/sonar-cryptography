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
 * Detection rules for Go's crypto/ecdsa package.
 *
 * <p>Detects usage of:
 *
 * <ul>
 *   <li>ecdsa.GenerateKey(c elliptic.Curve, rand io.Reader) - generates an ECDSA keypair
 *   <li>ecdsa.Sign(rand io.Reader, priv *PrivateKey, hash []byte) - signs a hash
 *   <li>ecdsa.Verify(pub *PublicKey, hash []byte, r, s *big.Int) - verifies a signature
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class GoCryptoECDSA {

    private GoCryptoECDSA() {
        // private
    }

    // ecdsa.GenerateKey(c elliptic.Curve, rand io.Reader) (*PrivateKey, error)
    // Generates a public and private key pair using the specified elliptic curve
    private static final IDetectionRule<Tree> GENERATE_KEY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/ecdsa")
                    .forMethods("GenerateKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDSA"))
                    .withMethodParameter("elliptic.Curve")
                    .addDependingDetectionRules(GoCryptoElliptic.rules())
                    .withMethodParameter("io.Reader")
                    .addDependingDetectionRules(GoCryptoRand.rules())
                    .buildForContext(new KeyContext(Map.of("kind", "ECDSA")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // ecdsa.Sign(rand io.Reader, priv *PrivateKey, hash []byte) (r, s *big.Int, err error)
    // Signs a hash (which should be the result of hashing a larger message)
    private static final IDetectionRule<Tree> SIGN =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/ecdsa")
                    .forMethods("Sign")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withMethodParameter("io.Reader")
                    .withMethodParameter("*ecdsa.PrivateKey")
                    .addDependingDetectionRules(List.of(GoCryptoECDSA.GENERATE_KEY))
                    .withMethodParameter("[]byte")
                    .buildForContext(new SignatureContext(Map.of("kind", "ECDSA")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // ecdsa.Verify(pub *PublicKey, hash []byte, r, s *big.Int) bool
    // Verifies the signature in r, s of hash using the public key
    private static final IDetectionRule<Tree> VERIFY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/ecdsa")
                    .forMethods("Verify")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withMethodParameter("*ecdsa.PublicKey")
                    .addDependingDetectionRules(List.of(GoCryptoECDSA.GENERATE_KEY))
                    .withMethodParameter("[]byte")
                    .withMethodParameter("*big.Int")
                    .withMethodParameter("*big.Int")
                    .buildForContext(new SignatureContext(Map.of("kind", "ECDSA")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // ecdsa.SignASN1(rand io.Reader, priv *PrivateKey, hash []byte) ([]byte, error)
    // Signs a hash using the private key, returning the ASN.1 encoded signature
    private static final IDetectionRule<Tree> SIGN_ASN1 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/ecdsa")
                    .forMethods("SignASN1")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withMethodParameter("io.Reader")
                    .addDependingDetectionRules(GoCryptoRand.rules())
                    .withMethodParameter("*ecdsa.PrivateKey")
                    .addDependingDetectionRules(List.of(GoCryptoECDSA.GENERATE_KEY))
                    .withMethodParameter("[]byte")
                    .buildForContext(new SignatureContext(Map.of("kind", "ECDSA")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // ecdsa.VerifyASN1(pub *PublicKey, hash, sig []byte) bool
    // Verifies the ASN.1 encoded signature of hash using the public key
    private static final IDetectionRule<Tree> VERIFY_ASN1 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/ecdsa")
                    .forMethods("VerifyASN1")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withMethodParameter("*ecdsa.PublicKey")
                    .addDependingDetectionRules(List.of(GoCryptoECDSA.GENERATE_KEY))
                    .withMethodParameter("[]byte")
                    .withMethodParameter("[]byte")
                    .buildForContext(new SignatureContext(Map.of("kind", "ECDSA")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(GENERATE_KEY, SIGN, VERIFY, SIGN_ASN1, VERIFY_ASN1);
    }
}
