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
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

/**
 * Detection rules for ML-DSA (FIPS 204) in .NET 9+.
 *
 * <p>Detects key generation for all three parameter sets:
 *
 * <ul>
 *   <li>{@code MLDsa44.GenerateKey()}
 *   <li>{@code MLDsa65.GenerateKey()}
 *   <li>{@code MLDsa87.GenerateKey()}
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class DotNetMLDsa {

    private DotNetMLDsa() {
        // nothing
    }

    private static IDetectionRule<CSharpTree> mlDsaRule(String className, String value) {
        return new DetectionRuleBuilder<CSharpTree>()
                .createDetectionRule()
                .forObjectTypes(className)
                .forMethods("GenerateKey")
                .shouldBeDetectedAs(new ValueActionFactory<>(value))
                .withMethodParameter(MethodMatcher.ANY)
                .buildForContext(new KeyContext(Map.of("kind", "MLDSA")))
                .inBundle(() -> "DotNet")
                .withoutDependingDetectionRules();
    }

    private static final IDetectionRule<CSharpTree> MLDSA_44 = mlDsaRule("MLDsa", "MLDSA44");

    private static final IDetectionRule<CSharpTree> MLDSA_65 = mlDsaRule("MLDsa", "MLDSA65");

    private static final IDetectionRule<CSharpTree> MLDSA_87 = mlDsaRule("MLDsa", "MLDSA87");

    @Nonnull
    public static List<IDetectionRule<CSharpTree>> rules() {
        return List.of(MLDSA_44, MLDSA_65, MLDSA_87);
    }
}
