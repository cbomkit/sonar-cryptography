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
 * Detection rules for ECDH usage in System.Security.Cryptography.
 *
 * <p>Detects:
 *
 * <ul>
 *   <li>{@code ECDiffieHellman.Create()} — abstract factory
 *   <li>{@code ECDiffieHellman.Create(curve)} — factory with ECCurve
 *   <li>{@code new ECDiffieHellmanCng()} — CNG-backed implementation
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class DotNetECDiffieHellman {

    private DotNetECDiffieHellman() {
        // nothing
    }

    private static final IDetectionRule<CSharpTree> ECDH_CREATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("ECDiffieHellman")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDH"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "ECDH")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    private static final IDetectionRule<CSharpTree> ECDH_CNG =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("ECDiffieHellmanCng")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDH"))
                    .withoutParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "ECDH")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    @Nonnull
    public static List<IDetectionRule<CSharpTree>> rules() {
        return List.of(ECDH_CREATE, ECDH_CNG);
    }
}
