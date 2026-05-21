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

import com.ibm.engine.model.AlgorithmParameter;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.factory.AlgorithmParameterFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcCMCEParameters {

    private BcCMCEParameters() {
        // nothing
    }

    private static final IDetectionRule<Tree> KEY_CONSTRUCTOR =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectExactTypes("org.bouncycastle.pqc.crypto.cmce.CMCEKeyParameters")
                    .forConstructor()
                    .withMethodParameter("boolean")
                    .withMethodParameter("org.bouncycastle.pqc.crypto.cmce.CMCEParameters")
                    .shouldBeDetectedAs(
                            new AlgorithmParameterFactory<>(AlgorithmParameter.Kind.ANY))
                    .buildForContext(new KeyContext())
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> PRIVATE_KEY_CONSTRUCTOR =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("org.bouncycastle.pqc.crypto.cmce.CMCEPrivateKeyParameters")
                    .forConstructor()
                    .withMethodParameter("org.bouncycastle.pqc.crypto.cmce.CMCEParameters")
                    .shouldBeDetectedAs(
                            new AlgorithmParameterFactory<>(AlgorithmParameter.Kind.ANY))
                    .withMethodParameter(BYTE_ARRAY_TYPE)
                    .withMethodParameter(BYTE_ARRAY_TYPE)
                    .withMethodParameter(BYTE_ARRAY_TYPE)
                    .withMethodParameter(BYTE_ARRAY_TYPE)
                    .withMethodParameter(BYTE_ARRAY_TYPE)
                    .buildForContext(new KeyContext())
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> PUBLIC_KEY_CONSTRUCTOR =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("org.bouncycastle.pqc.crypto.cmce.CMCEPublicKeyParameters")
                    .forConstructor()
                    .withMethodParameter("org.bouncycastle.pqc.crypto.cmce.CMCEParameters")
                    .shouldBeDetectedAs(
                            new AlgorithmParameterFactory<>(AlgorithmParameter.Kind.ANY))
                    .withMethodParameter(BYTE_ARRAY_TYPE)
                    .buildForContext(new KeyContext())
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(KEY_CONSTRUCTOR, PRIVATE_KEY_CONSTRUCTOR, PUBLIC_KEY_CONSTRUCTOR);
    }
}
