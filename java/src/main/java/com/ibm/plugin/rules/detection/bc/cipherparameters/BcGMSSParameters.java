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
package com.ibm.plugin.rules.detection.bc.cipherparameters;

import static com.ibm.plugin.rules.detection.TypeShortcuts.BYTE_ARRAY_TYPE;

import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.AlgorithmParameterContext;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcGMSSParameters {

    private BcGMSSParameters() {
        // nothing
    }

    /* This base constructor is not a CipherParameters class */
    private static final IDetectionRule<Tree> BASE_CONSTRUCTOR =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("org.bouncycastle.pqc.legacy.crypto.gmss.GMSSParameters")
                    .forConstructor()
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new AlgorithmParameterContext())
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> KEY_CONSTRUCTOR =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("org.bouncycastle.pqc.legacy.crypto.gmss.GMSSKeyParameters")
                    .forConstructor()
                    .withMethodParameter("boolean")
                    .withMethodParameter("org.bouncycastle.pqc.legacy.crypto.gmss.GMSSParameters")
                    .addDependingDetectionRules(List.of(BASE_CONSTRUCTOR))
                    .buildForContext(new AlgorithmParameterContext())
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> PUBLIC_KEY_CONSTRUCTOR =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(
                            "org.bouncycastle.pqc.legacy.crypto.gmss.GMSSPublicKeyParameters")
                    .forConstructor()
                    .withMethodParameter(BYTE_ARRAY_TYPE)
                    .withMethodParameter("org.bouncycastle.pqc.legacy.crypto.gmss.GMSSParameters")
                    .addDependingDetectionRules(List.of(BASE_CONSTRUCTOR))
                    .buildForContext(new AlgorithmParameterContext())
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> BCGMSS_PUBLIC_KEY_CONSTRUCTOR_1 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("org.bouncycastle.pqc.jcajce.provider.gmss.BCGMSSPublicKey")
                    .forConstructor()
                    .withMethodParameter(BYTE_ARRAY_TYPE)
                    .withMethodParameter("org.bouncycastle.pqc.legacy.crypto.gmss.GMSSParameters")
                    .addDependingDetectionRules(List.of(BASE_CONSTRUCTOR))
                    .buildForContext(new AlgorithmParameterContext())
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> BCGMSS_PUBLIC_KEY_CONSTRUCTOR_2 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("org.bouncycastle.pqc.jcajce.provider.gmss.BCGMSSPublicKey")
                    .forConstructor()
                    .withMethodParameter(
                            "org.bouncycastle.pqc.legacy.crypto.gmss.GMSSPublicKeyParameters")
                    .addDependingDetectionRules(List.of(PUBLIC_KEY_CONSTRUCTOR))
                    .buildForContext(new AlgorithmParameterContext())
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> PRIVATE_KEY_CONSTRUCTOR_1 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(
                            "org.bouncycastle.pqc.legacy.crypto.gmss.GMSSPrivateKeyParameters")
                    .forConstructor()
                    .withMethodParameter("byte[][]")
                    .withMethodParameter("byte[][]")
                    .withMethodParameter("byte[][][]")
                    .withMethodParameter("byte[][][]")
                    .withMethodParameter("org.bouncycastle.pqc.legacy.crypto.gmss.Treehash[][]")
                    .withMethodParameter("org.bouncycastle.pqc.legacy.crypto.gmss.Treehash[][]")
                    .withMethodParameter("java.util.Vector[]")
                    .withMethodParameter("java.util.Vector[]")
                    .withMethodParameter("java.util.Vector[][]")
                    .withMethodParameter("java.util.Vector[][]")
                    .withMethodParameter("byte[][]")
                    .withMethodParameter("byte[][]")
                    .withMethodParameter("org.bouncycastle.pqc.legacy.crypto.gmss.GMSSParameters")
                    .addDependingDetectionRules(List.of(BASE_CONSTRUCTOR))
                    .withMethodParameter(
                            "org.bouncycastle.pqc.legacy.crypto.gmss.GMSSDigestProvider")
                    .buildForContext(new AlgorithmParameterContext())
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> PRIVATE_KEY_CONSTRUCTOR_2 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(
                            "org.bouncycastle.pqc.legacy.crypto.gmss.GMSSPrivateKeyParameters")
                    .forConstructor()
                    .withMethodParameter("byte[][]")
                    .withMethodParameter("byte[][]")
                    .withMethodParameter("byte[][][]")
                    .withMethodParameter("byte[][][]")
                    .withMethodParameter("byte[][][]")
                    .withMethodParameter("org.bouncycastle.pqc.legacy.crypto.gmss.Treehash[][]")
                    .withMethodParameter("org.bouncycastle.pqc.legacy.crypto.gmss.Treehash[][]")
                    .withMethodParameter("java.util.Vector[]")
                    .withMethodParameter("java.util.Vector[]")
                    .withMethodParameter("java.util.Vector[][]")
                    .withMethodParameter("java.util.Vector[][]")
                    .withMethodParameter("org.bouncycastle.pqc.legacy.crypto.gmss.GMSSLeaf[]")
                    .withMethodParameter("org.bouncycastle.pqc.legacy.crypto.gmss.GMSSLeaf[]")
                    .withMethodParameter("org.bouncycastle.pqc.legacy.crypto.gmss.GMSSLeaf[]")
                    .withMethodParameter("int[]")
                    .withMethodParameter("byte[][]")
                    .withMethodParameter("org.bouncycastle.pqc.legacy.crypto.gmss.GMSSRootCalc[]")
                    .withMethodParameter("byte[][]")
                    .withMethodParameter("org.bouncycastle.pqc.legacy.crypto.gmss.GMSSRootSig[]")
                    .withMethodParameter("org.bouncycastle.pqc.legacy.crypto.gmss.GMSSParameters")
                    .addDependingDetectionRules(List.of(BASE_CONSTRUCTOR))
                    .withMethodParameter(
                            "org.bouncycastle.pqc.legacy.crypto.gmss.GMSSDigestProvider")
                    .buildForContext(new AlgorithmParameterContext())
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(
                    () ->
                            List.of(
                                    KEY_CONSTRUCTOR,
                                    PUBLIC_KEY_CONSTRUCTOR,
                                    BCGMSS_PUBLIC_KEY_CONSTRUCTOR_1,
                                    BCGMSS_PUBLIC_KEY_CONSTRUCTOR_2,
                                    PRIVATE_KEY_CONSTRUCTOR_1,
                                    PRIVATE_KEY_CONSTRUCTOR_2));

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }
}
