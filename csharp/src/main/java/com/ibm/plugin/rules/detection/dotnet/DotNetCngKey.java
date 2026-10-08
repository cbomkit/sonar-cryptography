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
package com.ibm.plugin.rules.detection.dotnet;

import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

/**
 * Detection rules for {@code CngKey} — the Windows-native (Cryptography Next Generation) path to
 * asymmetric key material.
 *
 * <p>{@code CngKey.Create(CngAlgorithm)} names the algorithm through a {@code CngAlgorithm} static
 * property, i.e. a member access such as {@code CngAlgorithm.Rsa} or {@code
 * CngAlgorithm.ECDsaP384}, which the engine resolves to the member name. {@code
 * CSharpKeyContextTranslator} maps those names onto the algorithm — and, for the curve-specific
 * spellings, onto the named curve as well, since {@code ECDsaP384} states the curve as
 * unambiguously as {@code ECCurve.NamedCurves.nistP384} does.
 *
 * <p>{@code CngKey.Open(string keyName)} and {@code CngKey.Import(byte[], CngKeyBlobFormat)} name
 * no algorithm at all — the algorithm is a property of the stored key, which is outside the source
 * — so they get no rule: reporting an unknown asymmetric algorithm would be a finding without
 * content.
 */
public final class DotNetCngKey extends DetectionRuleSet<CSharpTree> {

    /**
     * {@code CngKey.Create(CngAlgorithm algorithm)} — the algorithm always sits in the first
     * parameter, and the declared parameter type {@code CngAlgorithm} is checked by {@code
     * CSharpTypeInference}: a member access such as {@code CngAlgorithm.Rsa} infers to that type,
     * while an argument whose type cannot be determined is still allowed through.
     */
    private static final IDetectionRule<CSharpTree> CNG_KEY_CREATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("CngKey")
                    .forMethods("Create")
                    .withMethodParameter("CngAlgorithm")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new KeyContext(Map.of("kind", "CNG")))
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // CngKey.Create(CngAlgorithm algorithm, string keyName)
    private static final IDetectionRule<CSharpTree> CNG_KEY_CREATE_NAMED =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("CngKey")
                    .forMethods("Create")
                    .withMethodParameter("CngAlgorithm")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter(MethodMatcher.ANY) // keyName
                    .buildForContext(new KeyContext(Map.of("kind", "CNG")))
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // CngKey.Create(CngAlgorithm algorithm, string keyName, CngKeyCreationParameters parameters)
    private static final IDetectionRule<CSharpTree> CNG_KEY_CREATE_WITH_PARAMETERS =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("CngKey")
                    .forMethods("Create")
                    .withMethodParameter("CngAlgorithm")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter(MethodMatcher.ANY) // keyName
                    .withMethodParameter(MethodMatcher.ANY) // creation parameters
                    .buildForContext(new KeyContext(Map.of("kind", "CNG")))
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<CSharpTree>> buildRules() {
        return List.of(CNG_KEY_CREATE, CNG_KEY_CREATE_NAMED, CNG_KEY_CREATE_WITH_PARAMETERS);
    }
}
