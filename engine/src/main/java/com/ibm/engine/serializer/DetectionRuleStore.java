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
package com.ibm.engine.serializer;

import com.ibm.engine.detection.MethodMatcher;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.annotation.Nonnull;

/**
 * Class used to store IDetectionRule relevant information in order to later serialize it and export
 * it as JSON.
 */
public class DetectionRuleStore<T> {
    @Nonnull private String id;
    private boolean isEntryPoint;
    @Nonnull private MethodMatcher<T> matchers;
    @Nonnull private Map<String, Set<String>> parameterNextDetectionRules;
    @Nonnull private Set<String> nextDetectionRules;

    public DetectionRuleStore(@Nonnull MethodMatcher<T> matchers, boolean isEntryPoint) {
        this.id = getMatcherID(matchers);
        this.isEntryPoint = isEntryPoint;
        this.matchers = matchers;
        this.nextDetectionRules = new HashSet<>();
        this.parameterNextDetectionRules = new HashMap<>();
    }

    public void addParameterDependingRuleIDs(
            @Nonnull String parameter, @Nonnull List<String> dependingRuleIDs) {
        if (this.parameterNextDetectionRules.get(parameter) == null) {
            this.parameterNextDetectionRules.put(parameter, new HashSet<>(dependingRuleIDs));
        } else {
            this.parameterNextDetectionRules.get(parameter).addAll(dependingRuleIDs);
        }
    }

    public void addDependingRuleIDs(@Nonnull List<String> dependingRuleIDs) {
        this.nextDetectionRules.addAll(dependingRuleIDs);
    }

    public static <T> String getMatcherID(MethodMatcher<T> methodMatcher) {
        String stringID = "";
        for (String invokedObject : methodMatcher.getInvokedObjectTypeStringsSerializable()) {
            stringID += invokedObject + " ";
        }
        stringID += "| ";
        for (String methodName : methodMatcher.getMethodNamesSerializable()) {
            stringID += methodName + " ";
        }
        stringID += "| ";
        for (String parameterType : methodMatcher.getParameterTypesSerializable()) {
            stringID += parameterType + " ";
        }
        stringID += "| " + methodMatcher.isPrefixMatch();
        return stringID;
    }

    public String getId() {
        return id;
    }

    public boolean isEntryPoint() {
        return isEntryPoint;
    }

    public MethodMatcher<T> getMatchers() {
        return matchers;
    }

    public Map<String, Set<String>> getParameterNextDetectionRules() {
        return parameterNextDetectionRules;
    }

    public Set<String> getNextDetectionRules() {
        return nextDetectionRules;
    }
}
