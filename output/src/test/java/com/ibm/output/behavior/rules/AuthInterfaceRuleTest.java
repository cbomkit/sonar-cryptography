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

class AuthInterfaceRuleTest {

    private final AuthInterfaceRule rule = new AuthInterfaceRule();

    private BehaviorSignals signalsOf(AuthContext.Kind... kinds) {
        return new BehaviorSignals(Set.of(), Set.of(kinds));
    }

    @Test
    void jwtYieldsAuthenticatesAndValidatesToken() {
        assertThat(rule.apply(signalsOf(AuthContext.Kind.JWT)))
                .containsOnly(CryptoBehavior.AUTHENTICATES, CryptoBehavior.VALIDATES_TOKEN);
    }

    @Test
    void oauthYieldsAuthenticatesAndValidatesToken() {
        assertThat(rule.apply(signalsOf(AuthContext.Kind.OAUTH)))
                .containsOnly(CryptoBehavior.AUTHENTICATES, CryptoBehavior.VALIDATES_TOKEN);
    }

    @Test
    void samlYieldsAuthenticatesAndValidatesToken() {
        assertThat(rule.apply(signalsOf(AuthContext.Kind.SAML)))
                .containsOnly(CryptoBehavior.AUTHENTICATES, CryptoBehavior.VALIDATES_TOKEN);
    }

    @Test
    void principalYieldsAuthenticatesAndUsesIdentity() {
        assertThat(rule.apply(signalsOf(AuthContext.Kind.PRINCIPAL)))
                .containsOnly(CryptoBehavior.AUTHENTICATES, CryptoBehavior.USES_IDENTITY);
    }

    @Test
    void mtlsYieldsAuthenticatesAndUsesIdentity() {
        assertThat(rule.apply(signalsOf(AuthContext.Kind.MTLS)))
                .containsOnly(CryptoBehavior.AUTHENTICATES, CryptoBehavior.USES_IDENTITY);
    }

    @Test
    void apiKeyYieldsAuthenticatesOnly() {
        assertThat(rule.apply(signalsOf(AuthContext.Kind.API_KEY)))
                .containsOnly(CryptoBehavior.AUTHENTICATES);
    }

    @Test
    void noneKindIsNotAPrimary() {
        assertThat(rule.apply(signalsOf(AuthContext.Kind.NONE))).isEmpty();
    }

    @Test
    void noSignalsYieldNothing() {
        assertThat(rule.apply(signalsOf())).isEmpty();
    }

    @Test
    void multipleKindsUnionTheirContributions() {
        assertThat(rule.apply(signalsOf(AuthContext.Kind.JWT, AuthContext.Kind.PRINCIPAL)))
                .containsOnly(
                        CryptoBehavior.AUTHENTICATES,
                        CryptoBehavior.VALIDATES_TOKEN,
                        CryptoBehavior.USES_IDENTITY);
    }

    @Test
    void cryptoBehaviorsInTheSignalsAreIgnored() {
        final BehaviorSignals signals =
                new BehaviorSignals(Set.of(CryptoBehavior.ENCRYPTS_DATA), Set.of());
        assertThat(rule.apply(signals)).isEmpty();
    }
}
