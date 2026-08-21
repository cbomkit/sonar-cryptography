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
 * Detection rules for ML-KEM (FIPS 203) in .NET 9+.
 *
 * <p>Detects key generation for all three parameter sets:
 *
 * <ul>
 *   <li>{@code MLKem512.GenerateKey()}
 *   <li>{@code MLKem768.GenerateKey()}
 *   <li>{@code MLKem1024.GenerateKey()}
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class DotNetMLKem {

    private DotNetMLKem() {
        // nothing
    }

    private static IDetectionRule<CSharpTree> mlKemRule(String className, String value) {
        return new DetectionRuleBuilder<CSharpTree>()
                .createDetectionRule()
                .forObjectTypes(className)
                .forMethods("GenerateKey")
                .shouldBeDetectedAs(new ValueActionFactory<>(value))
                .withMethodParameter(MethodMatcher.ANY)
                .buildForContext(new KeyContext(Map.of("kind", "MLKEM")))
                .inBundle(() -> "DotNet")
                .withoutDependingDetectionRules();
    }

    private static final IDetectionRule<CSharpTree> MLKEM_512 = mlKemRule("MLKem", "MLKEM512");

    private static final IDetectionRule<CSharpTree> MLKEM_768 = mlKemRule("MLKem", "MLKEM768");

    private static final IDetectionRule<CSharpTree> MLKEM_1024 = mlKemRule("MLKem", "MLKEM1024");

    @Nonnull
    public static List<IDetectionRule<CSharpTree>> rules() {
        return List.of(MLKEM_512, MLKEM_768, MLKEM_1024);
    }
}
