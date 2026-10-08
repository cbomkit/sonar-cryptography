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
package com.ibm.plugin.rules.detection;

import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.model.factory.IActionFactory;
import com.ibm.engine.rule.DetectableParameter;
import com.ibm.engine.rule.DetectionRule;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.Parameter;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

/**
 * Detection rules derived from others that match the same calls with the same parameters and report
 * their values in another context, e.g. the digest getters ({@code EVP_sha256()}, ...) in the
 * context of the digest of MGF1. A derived rule detects the same as the rule it is derived from, so
 * a call reported through a derived rule is not reported again through the original rule, see
 * {@link #origin}.
 */
public final class DerivedDetectionRules {

    private static final Map<IDetectionRule<AstNode>, IDetectionRule<AstNode>> ORIGINS =
            Collections.synchronizedMap(new IdentityHashMap<>());

    private DerivedDetectionRules() {
        // utility
    }

    /**
     * The rules reporting their values in the given context, each derived from one of the given
     * rules. A rule that is not a {@link DetectionRule} is kept as it is.
     */
    @Nonnull
    public static List<IDetectionRule<AstNode>> withContext(
            @Nonnull List<IDetectionRule<AstNode>> rules, @Nonnull DetectionContext context) {
        return rules.stream().map(rule -> withContext(rule, context)).toList();
    }

    @Nonnull
    private static IDetectionRule<AstNode> withContext(
            @Nonnull IDetectionRule<AstNode> rule, @Nonnull DetectionContext context) {
        if (!(rule instanceof DetectionRule<AstNode> detectionRule)) {
            return rule;
        }
        final IDetectionRule<AstNode> derived =
                new DetectionRule<>(
                        detectionRule.matchers(),
                        detectionRule.shouldMatchExactTypes(),
                        detectionRule.parameters(),
                        detectionRule.actionFactory(),
                        context,
                        detectionRule.bundle(),
                        detectionRule.nextDetectionRules());
        ORIGINS.put(derived, origin(rule));
        return derived;
    }

    /**
     * The rule detecting the given action, with its values in the given context, derived from the
     * given rule, e.g. a setting of a key generation context that is a detection of its own when
     * the context is created elsewhere. The values the rule detects at its parameters are reported
     * below the action. The given rule must be a {@link DetectionRule}.
     */
    @Nonnull
    public static IDetectionRule<AstNode> withAction(
            @Nonnull IDetectionRule<AstNode> rule,
            @Nonnull IActionFactory<AstNode> actionFactory,
            @Nonnull DetectionContext context) {
        final DetectionRule<AstNode> detectionRule = (DetectionRule<AstNode>) rule;
        final List<Parameter<AstNode>> parameters =
                detectionRule.parameters().stream()
                        .map(DerivedDetectionRules::belowTheAction)
                        .toList();
        final IDetectionRule<AstNode> derived =
                new DetectionRule<>(
                        detectionRule.matchers(),
                        detectionRule.shouldMatchExactTypes(),
                        parameters,
                        actionFactory,
                        context,
                        detectionRule.bundle(),
                        detectionRule.nextDetectionRules());
        ORIGINS.put(derived, origin(rule));
        return derived;
    }

    /** The parameter, whose detected value, if it detects one, is reported below the action. */
    @Nonnull
    private static Parameter<AstNode> belowTheAction(@Nonnull Parameter<AstNode> parameter) {
        if (!(parameter instanceof DetectableParameter<AstNode> detectable)
                || detectable.getShouldBeMovedUnder().isPresent()) {
            return parameter;
        }
        return new DetectableParameter<>(
                detectable.getParameterType(),
                detectable.getIndex(),
                detectable.shouldMatchExactTypes(),
                detectable.getiValueFactory(),
                detectable.getDetectionRules(),
                -1);
    }

    /** The rule a rule is derived from, or the rule itself when it is not derived. */
    @Nonnull
    public static IDetectionRule<AstNode> origin(@Nonnull IDetectionRule<AstNode> rule) {
        final IDetectionRule<AstNode> origin = ORIGINS.get(rule);
        return origin == null ? rule : origin;
    }
}
