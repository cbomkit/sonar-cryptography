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
package com.ibm.output.behavior;

import com.ibm.engine.model.context.AuthContext;
import java.util.Set;
import javax.annotation.Nonnull;

/**
 * Immutable snapshot of every behavior-relevant signal observed during a scan — the single input to
 * each {@link IBehaviorRule}. A future evidence family (certificates, code signing) adds one
 * component here, one observe branch in {@link BehaviorCollector}, and one rule; nothing else
 * changes.
 */
public record BehaviorSignals(
        @Nonnull Set<CryptoBehavior> cryptoBehaviors, @Nonnull Set<AuthContext.Kind> authKinds) {

    public BehaviorSignals {
        cryptoBehaviors = Set.copyOf(cryptoBehaviors);
        authKinds = Set.copyOf(authKinds);
    }
}
