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
package com.ibm.plugin.rules.detection.nodecrypto;

import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.CipherActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.javascript.api.Tree;
import com.ibm.plugin.rules.detection.Memoize;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;

/** Detection rules for methods on Node.js {@code crypto.Decipher} objects. */
@SuppressWarnings("java:S1192")
public final class NodeCryptoDecipherStream {

    private NodeCryptoDecipherStream() {
        // private
    }

    private static final IDetectionRule<Tree> UPDATE =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.DECIPHER)
                    .forMethods("update")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.DECRYPT))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> FINAL =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.DECIPHER)
                    .forMethods("final")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.DECRYPT))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> SET_AAD =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.DECIPHER)
                    .forMethods("setAAD")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.DECRYPT))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> SET_AUTH_TAG =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.DECIPHER)
                    .forMethods("setAuthTag")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.DECRYPT))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(NodeCryptoDecipherStream::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        return List.of(UPDATE, FINAL, SET_AAD, SET_AUTH_TAG);
    }
}
