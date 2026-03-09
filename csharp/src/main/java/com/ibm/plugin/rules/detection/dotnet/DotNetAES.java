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
import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.model.factory.ModeFactory;
import com.ibm.engine.model.factory.PaddingFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for AES usage in System.Security.Cryptography.
 *
 * <p>Detects:
 *
 * <ul>
 *   <li>{@code Aes.Create()} — factory method on abstract base class
 *   <li>{@code new AesManaged()} — legacy concrete class (deprecated in .NET 6+)
 *   <li>{@code new AesGcm(key)} — authenticated encryption with GCM mode
 *   <li>{@code new AesCcm(key)} — authenticated encryption with CCM mode
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class DotNetAES {

    private DotNetAES() {
        // nothing
    }

    // aes.Mode = CipherMode.CBC  →  synthetic set_Mode(CipherMode.CBC)
    private static final IDetectionRule<CSharpTree> AES_SET_MODE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("set_Mode")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new ModeFactory<>())
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // aes.KeySize = 256  →  synthetic set_KeySize(256)
    private static final IDetectionRule<CSharpTree> AES_SET_KEY_SIZE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("set_KeySize")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // aes.Padding = PaddingMode.PKCS7  →  synthetic set_Padding(PaddingMode.PKCS7)
    private static final IDetectionRule<CSharpTree> AES_SET_PADDING =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("set_Padding")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new PaddingFactory<>())
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    private static final List<IDetectionRule<CSharpTree>> PROPERTY_SETTER_RULES =
            List.of(AES_SET_MODE, AES_SET_KEY_SIZE, AES_SET_PADDING);

    // Aes.Create() — abstract factory
    private static final IDetectionRule<CSharpTree> AES_CREATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("Aes")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(PROPERTY_SETTER_RULES);

    // new AesManaged() — legacy concrete class
    private static final IDetectionRule<CSharpTree> AES_MANAGED =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("AesManaged")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(PROPERTY_SETTER_RULES);

    // new AesCng() — CNG-backed implementation
    private static final IDetectionRule<CSharpTree> AES_CNG =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("AesCng")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(PROPERTY_SETTER_RULES);

    // new AesGcm(key) — GCM authenticated encryption
    // TODO: capture key parameter (byte[] key) to extract key length as a known gap
    private static final IDetectionRule<CSharpTree> AES_GCM =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("AesGcm")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // new AesCcm(key) — CCM authenticated encryption
    // TODO: capture key parameter (byte[] key) to extract key length as a known gap
    private static final IDetectionRule<CSharpTree> AES_CCM =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("AesCcm")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    @Nonnull
    public static List<IDetectionRule<CSharpTree>> rules() {
        return List.of(AES_CREATE, AES_MANAGED, AES_CNG, AES_GCM, AES_CCM);
    }
}
