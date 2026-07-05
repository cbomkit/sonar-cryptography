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
package com.ibm.plugin.rules.detection.jca.algorithmspec;

import static com.ibm.plugin.rules.detection.TypeShortcuts.BIGINTEGER_TYPE;
import static com.ibm.plugin.rules.detection.TypeShortcuts.BYTE_ARRAY_TYPE;

import com.ibm.engine.model.AlgorithmParameter;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.factory.AlgorithmParameterFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class JcaECParameterSpec {

    private static final IDetectionRule<Tree> EC_FIELD_P =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("java.security.spec.ECFieldFp")
                    .forConstructor()
                    .withMethodParameter(BIGINTEGER_TYPE)
                    .shouldBeDetectedAs(new AlgorithmParameterFactory<>(AlgorithmParameter.Kind.P))
                    .buildForContext(new PrivateKeyContext(KeyContext.Kind.EC))
                    .inBundle(() -> "Jca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> EC_FIELD_F2m_1 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("java.security.spec.ECFieldF2m")
                    .forConstructor()
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new AlgorithmParameterFactory<>(AlgorithmParameter.Kind.M))
                    .buildForContext(new PrivateKeyContext(KeyContext.Kind.EC))
                    .inBundle(() -> "Jca")
                    .withoutDependingDetectionRules();
    private static final IDetectionRule<Tree> EC_FIELD_F2m_2 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("java.security.spec.ECFieldF2m")
                    .forConstructor()
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new AlgorithmParameterFactory<>(AlgorithmParameter.Kind.M))
                    .withMethodParameter(BIGINTEGER_TYPE)
                    .buildForContext(new PrivateKeyContext(KeyContext.Kind.EC))
                    .inBundle(() -> "Jca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> EC_FIELD_F2m_3 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("java.security.spec.ECFieldF2m")
                    .forConstructor()
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new AlgorithmParameterFactory<>(AlgorithmParameter.Kind.M))
                    .withMethodParameter("int[]")
                    .buildForContext(new PrivateKeyContext(KeyContext.Kind.EC))
                    .inBundle(() -> "Jca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> EC_PARAMETER_SPEC =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("java.security.spec.ECParameterSpec")
                    .forConstructor()
                    .withMethodParameter("java.security.spec.EllipticCurve")
                    .addDependingDetectionRules(
                            List.of(
                                    new DetectionRuleBuilder<Tree>()
                                            .createDetectionRule()
                                            .forObjectTypes("java.security.spec.EllipticCurve")
                                            .forConstructor()
                                            .withMethodParameter("java.security.spec.ECField")
                                            .addDependingDetectionRules(
                                                    List.of(
                                                            EC_FIELD_P,
                                                            EC_FIELD_F2m_1,
                                                            EC_FIELD_F2m_2,
                                                            EC_FIELD_F2m_3))
                                            .withMethodParameter(BIGINTEGER_TYPE)
                                            .shouldBeDetectedAs(
                                                    new AlgorithmParameterFactory<>(
                                                            AlgorithmParameter.Kind.A))
                                            .withMethodParameter(BIGINTEGER_TYPE)
                                            .shouldBeDetectedAs(
                                                    new AlgorithmParameterFactory<>(
                                                            AlgorithmParameter.Kind.B))
                                            .buildForContext(
                                                    new PrivateKeyContext(KeyContext.Kind.EC))
                                            .inBundle(() -> "Jca")
                                            .withoutDependingDetectionRules(),
                                    new DetectionRuleBuilder<Tree>()
                                            .createDetectionRule()
                                            .forObjectTypes("java.security.spec.EllipticCurve")
                                            .forConstructor()
                                            .withMethodParameter("java.security.spec.ECField")
                                            .addDependingDetectionRules(
                                                    List.of(
                                                            EC_FIELD_P,
                                                            EC_FIELD_F2m_1,
                                                            EC_FIELD_F2m_2,
                                                            EC_FIELD_F2m_3))
                                            .withMethodParameter(BIGINTEGER_TYPE)
                                            .shouldBeDetectedAs(
                                                    new AlgorithmParameterFactory<>(
                                                            AlgorithmParameter.Kind.A))
                                            .withMethodParameter(BIGINTEGER_TYPE)
                                            .shouldBeDetectedAs(
                                                    new AlgorithmParameterFactory<>(
                                                            AlgorithmParameter.Kind.B))
                                            .withMethodParameter(BYTE_ARRAY_TYPE)
                                            .buildForContext(
                                                    new PrivateKeyContext(KeyContext.Kind.EC))
                                            .inBundle(() -> "Jca")
                                            .withoutDependingDetectionRules()))
                    .withMethodParameter("java.security.spec.ECPoint")
                    .withMethodParameter(BIGINTEGER_TYPE)
                    .shouldBeDetectedAs(new AlgorithmParameterFactory<>(AlgorithmParameter.Kind.N))
                    .withMethodParameter("int")
                    .buildForContext(new PrivateKeyContext(KeyContext.Kind.EC))
                    .inBundle(() -> "Jca")
                    .withoutDependingDetectionRules();

    private JcaECParameterSpec() {
        // nothing
    }

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(JcaECParameterSpec::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        return List.of(EC_PARAMETER_SPEC);
    }
}
