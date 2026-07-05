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
package com.ibm.plugin.rules;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.rule.DetectionRule;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.Parameter;
import com.ibm.plugin.rules.detection.JavaDetectionRules;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Deque;
import java.util.IdentityHashMap;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Guards the fix for issue #476: memoization must keep the distinct-object footprint of the Java
 * detection-rule graph far below its pre-fix size (~521k objects). Counts distinct
 * DetectionRule/MethodDetectionRule instances reachable via nextDetectionRules() and
 * parameter-attached depending rules, deduped by object identity.
 */
class RuleGraphMemoizationTest {

    /**
     * Pre-fix distinct-object count was ~521,017; memoization targets the low tens of thousands.
     */
    private static final int MAX_DISTINCT_RULES = 60_000;

    @Test
    void distinctRuleObjectFootprintStaysSmall() {
        Set<IDetectionRule<?>> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        Deque<IDetectionRule<?>> stack = new ArrayDeque<>(JavaDetectionRules.rules());

        while (!stack.isEmpty()) {
            IDetectionRule<?> rule = stack.pop();
            if (!seen.add(rule)) {
                continue;
            }
            stack.addAll(rule.nextDetectionRules());
            if (rule instanceof DetectionRule<?> detectionRule) {
                for (Parameter<?> parameter : detectionRule.parameters()) {
                    stack.addAll(parameter.getDetectionRules());
                }
            }
        }

        System.out.println("[#476] distinct reachable rule objects = " + seen.size());
        assertThat(seen.size()).isLessThan(MAX_DISTINCT_RULES);
    }
}
