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

import com.ibm.engine.model.context.AuthContext;
import com.ibm.output.behavior.BehaviorSignals;
import com.ibm.output.behavior.CryptoBehavior;
import com.ibm.output.behavior.IBehaviorRule;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;
import javax.annotation.Nonnull;

/**
 * Contributes application-level behaviors from detected auth-interface evidence (design 2026-07-13
 * §4). Crypto alone never asserts these: a MAC yields only {@code ensuresIntegrity} from the
 * mapper, and {@code authenticates} appears iff an auth interface was observed. SAML validates a
 * signed assertion (a bearer credential), so it also yields {@code validatesToken}; PRINCIPAL and
 * MTLS yield {@code usesIdentity} via the authenticated peer principal.
 */
public final class AuthInterfaceRule implements IBehaviorRule {

    // NONE is deliberately absent: it is the "no auth context" marker, never a primary.
    private static final Map<AuthContext.Kind, Set<CryptoBehavior>> CONTRIBUTIONS =
            Map.of(
                    AuthContext.Kind.JWT,
                            Set.of(CryptoBehavior.AUTHENTICATES, CryptoBehavior.VALIDATES_TOKEN),
                    AuthContext.Kind.OAUTH,
                            Set.of(CryptoBehavior.AUTHENTICATES, CryptoBehavior.VALIDATES_TOKEN),
                    AuthContext.Kind.SAML,
                            Set.of(CryptoBehavior.AUTHENTICATES, CryptoBehavior.VALIDATES_TOKEN),
                    AuthContext.Kind.PRINCIPAL,
                            Set.of(CryptoBehavior.AUTHENTICATES, CryptoBehavior.USES_IDENTITY),
                    AuthContext.Kind.MTLS,
                            Set.of(CryptoBehavior.AUTHENTICATES, CryptoBehavior.USES_IDENTITY),
                    AuthContext.Kind.API_KEY, Set.of(CryptoBehavior.AUTHENTICATES));

    @Override
    @Nonnull
    public Set<CryptoBehavior> apply(@Nonnull BehaviorSignals signals) {
        final Set<CryptoBehavior> result = EnumSet.noneOf(CryptoBehavior.class);
        for (AuthContext.Kind kind : signals.authKinds()) {
            result.addAll(CONTRIBUTIONS.getOrDefault(kind, Set.of()));
        }
        return result;
    }
}
