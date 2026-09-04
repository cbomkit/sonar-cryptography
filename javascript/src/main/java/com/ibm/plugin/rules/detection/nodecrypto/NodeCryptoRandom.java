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

import static com.ibm.engine.detection.MethodMatcher.ANY;

import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.PRNGContext;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.javascript.api.Tree;
import com.ibm.plugin.rules.detection.Memoize;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;

/**
 * Detection rules for Node.js cryptographically secure random number generation APIs.
 *
 * <p>Detects usage of:
 *
 * <ul>
 *   <li>crypto.randomBytes(size) - generates random bytes
 *   <li>crypto.randomFill(buffer, callback) - fills a buffer with random bytes
 *   <li>crypto.randomFillSync(buffer) - synchronous random fill
 *   <li>crypto.randomInt([min, ] max[, callback]) - generates a random integer
 *   <li>crypto.randomUUID() - generates a random UUID v4
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class NodeCryptoRandom {

    private NodeCryptoRandom() {
        // private
    }

    private static final IDetectionRule<Tree> RANDOM_BYTES =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.CRYPTO, NodeCryptoTypes.NODE_CRYPTO)
                    .forMethods("randomBytes")
                    .shouldBeDetectedAs(new ValueActionFactory<>("NATIVEPRNG"))
                    .withMethodParameter("number")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> RANDOM_BYTES_WITH_CALLBACK =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.CRYPTO, NodeCryptoTypes.NODE_CRYPTO)
                    .forMethods("randomBytes")
                    .shouldBeDetectedAs(new ValueActionFactory<>("NATIVEPRNG"))
                    .withMethodParameter("number")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter(ANY)
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> RANDOM_FILL =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.CRYPTO, NodeCryptoTypes.NODE_CRYPTO)
                    .forMethods("randomFill")
                    .shouldBeDetectedAs(new ValueActionFactory<>("NATIVEPRNG"))
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> RANDOM_FILL_SYNC =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.CRYPTO, NodeCryptoTypes.NODE_CRYPTO)
                    .forMethods("randomFillSync")
                    .shouldBeDetectedAs(new ValueActionFactory<>("NATIVEPRNG"))
                    .withMethodParameter(ANY)
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> RANDOM_INT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.CRYPTO, NodeCryptoTypes.NODE_CRYPTO)
                    .forMethods("randomInt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("NATIVEPRNG"))
                    .withAnyParameters()
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> RANDOM_UUID =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.CRYPTO, NodeCryptoTypes.NODE_CRYPTO)
                    .forMethods("randomUUID")
                    .shouldBeDetectedAs(new ValueActionFactory<>("NATIVEPRNG"))
                    .withoutParameters()
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(NodeCryptoRandom::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        return List.of(
                RANDOM_BYTES,
                RANDOM_BYTES_WITH_CALLBACK,
                RANDOM_FILL,
                RANDOM_FILL_SYNC,
                RANDOM_INT,
                RANDOM_UUID);
    }
}
