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
package com.ibm.plugin.rules.detection.asymmetric;

import static com.ibm.engine.detection.MethodMatcher.ANY;

import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.SignatureAction;
import com.ibm.engine.model.context.KeyAgreementContext;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.context.PublicKeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.CurveFactory;
import com.ibm.engine.model.factory.KeyActionFactory;
import com.ibm.engine.model.factory.SignatureActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.hash.PycaHash;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class PycaEllipticCurve {

    private PycaEllipticCurve() {
        // private
    }

    private static final String TYPE = "cryptography.hazmat.primitives.asymmetric.ec";
    private static final String GENERATE_METHOD = "generate_private_key";

    // ECDSA is the only algorithm accepted as in the sign/verify functions (it is the only subclass
    // of EllipticCurveSignatureAlgorithm)
    private static final IDetectionRule<Tree> ECDSA_EC =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(TYPE)
                    .forMethods("ECDSA")
                    .withMethodParameter(
                            "cryptography.hazmat.primitives.*") // This "type" accepts both hashes
                    // and pre-hashes
                    .addDependingDetectionRules(
                            PycaHash.rules()) // The parameter of ECDSA can either be an immediate
                    // hash, or a hash enclosed in the pre-hash function
                    .buildForContext(new SignatureContext(Map.of("algorithm", "ECDSA")))
                    .inBundle(() -> "Pyca")
                    .withoutDependingDetectionRules();

    public static final IDetectionRule<Tree> KEY_EXCHANGE_EC =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(TYPE + "." + GENERATE_METHOD)
                    .forMethods("exchange")
                    .withMethodParameter(TYPE + ".*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter(ANY)
                    .buildForContext(new KeyAgreementContext(Map.of("algorithm", "EC")))
                    .inBundle(() -> "Pyca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> SIGN_EC =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(TYPE + "." + GENERATE_METHOD)
                    .forMethods("sign")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withMethodParameter(ANY)
                    .withMethodParameter(TYPE + ".*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .addDependingDetectionRules(List.of(ECDSA_EC))
                    .buildForContext(new SignatureContext(Map.of("algorithm", "EC")))
                    .inBundle(() -> "Pyca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> GENERATION_EC =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(TYPE)
                    .forMethods(GENERATE_METHOD)
                    .withMethodParameter(ANY)
                    .shouldBeDetectedAs(new CurveFactory<>())
                    .buildForContext(new PrivateKeyContext(Map.of("algorithm", "EC")))
                    .inBundle(() -> "Pyca")
                    .withDependingDetectionRules(List.of(SIGN_EC, KEY_EXCHANGE_EC));

    private static final IDetectionRule<Tree> DERIVATION_EC =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(TYPE)
                    .forMethods("derive_private_key")
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .shouldBeDetectedAs(new CurveFactory<>())
                    .buildForContext(new PrivateKeyContext(Map.of("algorithm", "EC")))
                    .inBundle(() -> "Pyca")
                    .withDependingDetectionRules(List.of(SIGN_EC, KEY_EXCHANGE_EC));

    // Private numbers relies on information (the curve) given by the public key
    // For now; we only use it as a depending detection rule of PRIVATE_NUMBERS_EC
    private static final IDetectionRule<Tree> PRIVATE_NUMBERS_EC =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(TYPE)
                    .forMethods("EllipticCurvePrivateNumbers")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.GENERATION))
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .buildForContext(new PrivateKeyContext(Map.of("algorithm", "EC")))
                    .inBundle(() -> "Pyca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> PUBLIC_NUMBERS_EC =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(TYPE)
                    .forMethods("EllipticCurvePublicNumbers")
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new PublicKeyContext(Map.of("algorithm", "EC")))
                    .inBundle(() -> "Pyca")
                    .withDependingDetectionRules(List.of(PRIVATE_NUMBERS_EC));

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(PycaEllipticCurve::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        return List.of(GENERATION_EC, DERIVATION_EC, PUBLIC_NUMBERS_EC);
    }
}
