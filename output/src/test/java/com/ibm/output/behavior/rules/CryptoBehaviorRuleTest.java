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

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.model.context.AuthContext;
import com.ibm.output.behavior.BehaviorSignals;
import com.ibm.output.behavior.CryptoBehavior;
import java.util.Set;
import org.junit.jupiter.api.Test;

class CryptoBehaviorRuleTest {

    private final CryptoBehaviorRule rule = new CryptoBehaviorRule();

    @Test
    void passesCryptoBehaviorsThroughUnchanged() {
        final BehaviorSignals signals =
                new BehaviorSignals(
                        Set.of(
                                CryptoBehavior.ENCRYPTS_DATA,
                                CryptoBehavior.ENSURES_CONFIDENTIALITY),
                        Set.of(AuthContext.Kind.JWT));
        assertThat(rule.apply(signals))
                .containsOnly(CryptoBehavior.ENCRYPTS_DATA, CryptoBehavior.ENSURES_CONFIDENTIALITY);
    }

    @Test
    void emptySignalsYieldNothing() {
        assertThat(rule.apply(new BehaviorSignals(Set.of(), Set.of()))).isEmpty();
    }
}
