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

import com.ibm.engine.model.AlgorithmParameter;
import com.ibm.engine.model.SignatureAction;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.AlgorithmParameterFactory;
import com.ibm.engine.model.factory.SignatureActionFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.sonar.plugins.go.api.Tree;

/**
 * Detection rules for Go's crypto/dsa package.
 *
 * <p>Detects usage of:
 *
 * <ul>
 *   <li>dsa.GenerateParameters() - generates DSA domain parameters
 *   <li>dsa.GenerateKey() - generates a DSA key pair
 *   <li>dsa.Sign() - signs a hash using DSA
 *   <li>dsa.Verify() - verifies a DSA signature
 * </ul>
 *
 * <p>Note: DSA is deprecated in Go. FIPS 186-5 no longer approves DSA for signature generation.
 */
@SuppressWarnings("java:S1192")
public final class GoCryptoDSA {

    private GoCryptoDSA() {
        // private
    }

    // dsa.GenerateParameters(params *Parameters, rand io.Reader, sizes ParameterSizes) error
    // Generates DSA domain parameters
    private static final IDetectionRule<Tree> GENERATE_PARAMETERS =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/dsa")
                    .forMethods("GenerateParameters")
                    .withMethodParameter("*dsa.Parameters")
                    .withMethodParameter("io.Reader")
                    .withMethodParameter("dsa.ParameterSizes")
                    .shouldBeDetectedAs(
                            new AlgorithmParameterFactory<>(AlgorithmParameter.Kind.DSA_L_AND_N))
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new KeyContext(Map.of("kind", "DSA")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // dsa.GenerateKey(priv *PrivateKey, rand io.Reader) error
    // Generates a public and private key pair
    private static final IDetectionRule<Tree> GENERATE_KEY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/dsa")
                    .forMethods("GenerateKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DSA"))
                    .withMethodParameter("*dsa.PrivateKey")
                    .addDependingDetectionRules(List.of(GENERATE_PARAMETERS))
                    .withMethodParameter("io.Reader")
                    .buildForContext(new KeyContext(Map.of("kind", "DSA")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // dsa.Sign(rand io.Reader, priv *PrivateKey, hash []byte) (r, s *big.Int, err error)
    // Signs a hash using the private key
    private static final IDetectionRule<Tree> SIGN =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/dsa")
                    .forMethods("Sign")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withMethodParameter("io.Reader")
                    .withMethodParameter("*dsa.PrivateKey")
                    .addDependingDetectionRules(List.of(GENERATE_KEY))
                    .withMethodParameter("[]byte")
                    .buildForContext(new SignatureContext(Map.of("kind", "DSA")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // dsa.Verify(pub *PublicKey, hash []byte, r, s *big.Int) bool
    // Verifies a DSA signature
    private static final IDetectionRule<Tree> VERIFY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/dsa")
                    .forMethods("Verify")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withMethodParameter("*dsa.PublicKey")
                    .addDependingDetectionRules(List.of(GENERATE_KEY))
                    .withMethodParameter("[]byte")
                    .withMethodParameter("*big.Int")
                    .withMethodParameter("*big.Int")
                    .buildForContext(new SignatureContext(Map.of("kind", "DSA")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(GENERATE_KEY, SIGN, VERIFY);
    }
}
