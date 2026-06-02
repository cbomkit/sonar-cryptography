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
 * Detection rules for DSA usage in System.Security.Cryptography.
 *
 * <p>Detects:
 *
 * <ul>
 *   <li>{@code DSA.Create()} — abstract factory
 *   <li>{@code new DSACryptoServiceProvider()} — CAPI-backed implementation
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class DotNetDSA {

    private DotNetDSA() {
        // nothing
    }

    private static final IDetectionRule<CSharpTree> DSA_CREATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("DSA")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DSA"))
                    .withoutParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "DSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    private static final IDetectionRule<CSharpTree> DSA_CSP =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("DSACryptoServiceProvider")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DSA"))
                    .withoutParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "DSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    @Nonnull
    public static List<IDetectionRule<CSharpTree>> rules() {
        return List.of(DSA_CREATE, DSA_CSP);
    }
}
