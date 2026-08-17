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
package com.ibm.output.behavior.rules;

import com.ibm.output.behavior.BehaviorSignals;
import com.ibm.output.behavior.CryptoBehavior;
import com.ibm.output.behavior.IBehaviorRule;
import java.util.Set;
import javax.annotation.Nonnull;

/**
 * Passes the crypto-derived behaviors (the union of {@code CryptoBehaviorMapper} output across all
 * assets) through unchanged. The mapper never derives application-level behaviors, so no gating is
 * needed here.
 */
public final class CryptoBehaviorRule implements IBehaviorRule {

    @Override
    @Nonnull
    public Set<CryptoBehavior> apply(@Nonnull BehaviorSignals signals) {
        return signals.cryptoBehaviors();
    }
}
