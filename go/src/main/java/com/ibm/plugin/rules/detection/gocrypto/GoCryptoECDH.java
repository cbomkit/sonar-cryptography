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
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.sonar.plugins.go.api.Tree;

/**
 * Detection rules for Go's crypto/ecdh package.
 *
 * <p>Detects usage of:
 *
 * <ul>
 *   <li>ecdh.P256().GenerateKey() - generates an ECDH key pair using P-256 curve
 *   <li>ecdh.P384().GenerateKey() - generates an ECDH key pair using P-384 curve
 *   <li>ecdh.P521().GenerateKey() - generates an ECDH key pair using P-521 curve
 *   <li>ecdh.X25519().GenerateKey() - generates an ECDH key pair using X25519 curve
 *   <li>PrivateKey.ECDH() - performs ECDH key exchange
 *   <li>Curve.NewPrivateKey() - creates a PrivateKey from raw bytes (key import)
 *   <li>Curve.NewPublicKey() - creates a PublicKey from raw bytes (key import)
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class GoCryptoECDH {

    private GoCryptoECDH() {
        // private
    }

    // ecdh.P256() returns a Curve that implements P-256 (FIPS 186-3, section D.2.3)
    private static final IDetectionRule<Tree> P256 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/ecdh")
                    .forMethods("P256")
                    .shouldBeDetectedAs(new ValueActionFactory<>("P256"))
                    .withoutParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "ECDH")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // ecdh.P384() returns a Curve that implements P-384 (FIPS 186-3, section D.2.4)
    private static final IDetectionRule<Tree> P384 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/ecdh")
                    .forMethods("P384")
                    .shouldBeDetectedAs(new ValueActionFactory<>("P384"))
                    .withoutParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "ECDH")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // ecdh.P521() returns a Curve that implements P-521 (FIPS 186-3, section D.2.5)
    private static final IDetectionRule<Tree> P521 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/ecdh")
                    .forMethods("P521")
                    .shouldBeDetectedAs(new ValueActionFactory<>("P521"))
                    .withoutParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "ECDH")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // ecdh.X25519() returns a Curve that implements X25519 (RFC 7748)
    private static final IDetectionRule<Tree> X25519 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/ecdh")
                    .forMethods("X25519")
                    .shouldBeDetectedAs(new ValueActionFactory<>("X25519"))
                    .withoutParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "ECDH")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // Curve.GenerateKey(rand io.Reader) (*PrivateKey, error)
    // Generates a new private key for the curve
    private static final IDetectionRule<Tree> GENERATE_KEY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("*ecdh.Curve", "ecdh.Curve")
                    .forMethods("GenerateKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDH"))
                    .withMethodParameter("*")
                    .buildForContext(new KeyContext(Map.of("kind", "ECDH")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // PrivateKey.ECDH(remote *PublicKey) ([]byte, error)
    // Performs an ECDH exchange and returns the shared secret
    private static final IDetectionRule<Tree> ECDH_EXCHANGE =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("*ecdh.PrivateKey")
                    .forMethods("ECDH")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDH"))
                    .withMethodParameter("*")
                    .buildForContext(new KeyContext(Map.of("kind", "ECDH")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // Curve.NewPrivateKey(key []byte) (*PrivateKey, error)
    // Creates a PrivateKey from existing raw bytes (key import)
    private static final IDetectionRule<Tree> NEW_PRIVATE_KEY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("*ecdh.Curve", "ecdh.Curve")
                    .forMethods("NewPrivateKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDH"))
                    .withMethodParameter("*")
                    .buildForContext(new KeyContext(Map.of("kind", "ECDH")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // Curve.NewPublicKey(key []byte) (*PublicKey, error)
    // Creates a PublicKey from existing raw bytes (key import)
    private static final IDetectionRule<Tree> NEW_PUBLIC_KEY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("*ecdh.Curve", "ecdh.Curve")
                    .forMethods("NewPublicKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDH"))
                    .withMethodParameter("*")
                    .buildForContext(new KeyContext(Map.of("kind", "ECDH")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(
                P256,
                P384,
                P521,
                X25519,
                GENERATE_KEY,
                ECDH_EXCHANGE,
                NEW_PRIVATE_KEY,
                NEW_PUBLIC_KEY);
    }
}
