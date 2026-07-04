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
package com.ibm.output.cyclonedx.behavior;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.model.context.AuthContext;
import com.ibm.output.cyclondx.behavior.BehaviorInferenceEngine;
import com.ibm.output.cyclondx.behavior.Confidence;
import com.ibm.output.cyclondx.behavior.CryptoBehavior;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class BehaviorInferenceEngineTest {

    private final BehaviorInferenceEngine engine = new BehaviorInferenceEngine();

    @Test
    void macAloneDoesNotAuthenticate() {
        final Map<CryptoBehavior, Confidence> result =
                engine.infer(
                        EnumSet.of(CryptoBehavior.AUTHENTICATES, CryptoBehavior.ENSURES_INTEGRITY),
                        Set.of());
        assertThat(result).doesNotContainKey(CryptoBehavior.AUTHENTICATES);
        assertThat(result).containsEntry(CryptoBehavior.ENSURES_INTEGRITY, Confidence.HIGH);
    }

    @Test
    void macPlusJwtAuthenticatesAndValidatesToken() {
        final Map<CryptoBehavior, Confidence> result =
                engine.infer(
                        EnumSet.of(CryptoBehavior.AUTHENTICATES, CryptoBehavior.ENSURES_INTEGRITY),
                        Set.of(AuthContext.Kind.JWT));
        assertThat(result).containsEntry(CryptoBehavior.AUTHENTICATES, Confidence.HIGH);
        assertThat(result).containsEntry(CryptoBehavior.VALIDATES_TOKEN, Confidence.HIGH);
        assertThat(result).containsEntry(CryptoBehavior.ENSURES_INTEGRITY, Confidence.HIGH);
    }

    @Test
    void jwtWithoutCryptoStillYieldsTokenBehaviors() {
        final Map<CryptoBehavior, Confidence> result =
                engine.infer(EnumSet.noneOf(CryptoBehavior.class), Set.of(AuthContext.Kind.JWT));
        assertThat(result)
                .containsOnlyKeys(CryptoBehavior.AUTHENTICATES, CryptoBehavior.VALIDATES_TOKEN);
    }

    @Test
    void principalYieldsUsesIdentityAndCorroboratesAuthenticates() {
        final Map<CryptoBehavior, Confidence> result =
                engine.infer(
                        EnumSet.noneOf(CryptoBehavior.class), Set.of(AuthContext.Kind.PRINCIPAL));
        assertThat(result).containsEntry(CryptoBehavior.USES_IDENTITY, Confidence.HIGH);
        assertThat(result).containsEntry(CryptoBehavior.AUTHENTICATES, Confidence.HIGH);
        assertThat(result).doesNotContainKey(CryptoBehavior.VALIDATES_TOKEN);
    }

    @Test
    void cryptoOnlyPassesThroughUnchanged() {
        final Map<CryptoBehavior, Confidence> result =
                engine.infer(
                        EnumSet.of(
                                CryptoBehavior.ENCRYPTS_DATA,
                                CryptoBehavior.ENSURES_CONFIDENTIALITY),
                        Set.of());
        assertThat(result)
                .containsOnly(
                        Map.entry(CryptoBehavior.ENCRYPTS_DATA, Confidence.HIGH),
                        Map.entry(CryptoBehavior.ENSURES_CONFIDENTIALITY, Confidence.HIGH));
    }

    @Test
    void noneKindIsNotAPrimary() {
        final Map<CryptoBehavior, Confidence> result =
                engine.infer(EnumSet.noneOf(CryptoBehavior.class), Set.of(AuthContext.Kind.NONE));
        assertThat(result).isEmpty();
    }
}
