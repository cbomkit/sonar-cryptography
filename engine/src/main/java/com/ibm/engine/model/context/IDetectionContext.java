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
package com.ibm.engine.model.context;

import javax.annotation.Nonnull;

/**
 * Implementations are used as cache keys by {@link com.ibm.engine.rule.RuleSets}, so they must
 * implement value-based {@code equals}/{@code hashCode} covering all of their state, including any
 * state added by a subclass. A context that compares equal to a sibling with different state would
 * make {@code RuleSets} hand that sibling's cached rules back to the wrong caller.
 */
public interface IDetectionContext {

    @Nonnull
    Class<? extends IDetectionContext> type();

    default boolean is(@Nonnull Class<? extends IDetectionContext> kind) {
        return kind.equals(type());
    }
}
