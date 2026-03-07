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

import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

/**
 * Detection rules for RSA usage in System.Security.Cryptography.
 *
 * <p>Detects:
 *
 * <ul>
 *   <li>{@code RSA.Create()} — abstract factory, no key size
 *   <li>{@code RSA.Create(2048)} — factory with key size
 *   <li>{@code new RSACryptoServiceProvider()} — CAPI-backed, no key size
 *   <li>{@code new RSACryptoServiceProvider(2048)} — CAPI-backed with key size
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class DotNetRSA {

    private DotNetRSA() {
        // nothing
    }

    private static final IDetectionRule<CSharpTree> RSA_CREATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("RSA")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "RSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    private static final IDetectionRule<CSharpTree> RSA_CRYPTO_SERVICE_PROVIDER =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("RSACryptoServiceProvider")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "RSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    @Nonnull
    public static List<IDetectionRule<CSharpTree>> rules() {
        return List.of(RSA_CREATE, RSA_CRYPTO_SERVICE_PROVIDER);
    }
}
