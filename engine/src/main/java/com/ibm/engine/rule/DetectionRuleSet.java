/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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
package com.ibm.engine.rule;

import java.util.List;
import javax.annotation.Nonnull;

/**
 * A named group of detection rules. Subclasses only describe how to build their rules; the caching
 * is owned by {@link RuleSets}, which is the only way to read them.
 *
 * <p>{@code buildRules()} is {@code protected} on purpose: nothing outside this package can call
 * it, so no caller can rebuild a subtree that is meant to be shared (see issue #476).
 */
public abstract class DetectionRuleSet<T> {

    protected DetectionRuleSet() {
        // only subclasses
    }

    @Nonnull
    protected abstract List<IDetectionRule<T>> buildRules();
}
