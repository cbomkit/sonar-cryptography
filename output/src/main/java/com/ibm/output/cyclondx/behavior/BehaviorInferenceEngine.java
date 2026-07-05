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
package com.ibm.output.cyclondx.behavior;

import com.ibm.engine.model.context.AuthContext;
import java.util.EnumSet;
import java.util.Set;
import javax.annotation.Nonnull;

/**
 * Two-tier behavior inference (design §5). Combines crypto-derived behaviors with scan-wide
 * contextual auth signals. Crypto operational/goal behaviors pass through unchanged.
 * Application-level behaviors ({@code authenticates}, {@code validatesToken}, {@code usesIdentity})
 * are gated behind a required auth-interface primary: crypto alone can never assert them. Total and
 * side-effect free; never throws.
 */
public final class BehaviorInferenceEngine {

    @Nonnull
    public Set<CryptoBehavior> infer(
            @Nonnull Set<CryptoBehavior> cryptoBehaviors,
            @Nonnull Set<AuthContext.Kind> authSignals) {
        final Set<CryptoBehavior> result = EnumSet.noneOf(CryptoBehavior.class);

        // Crypto behaviors pass through, except AUTHENTICATES which is gated below:
        // a MAC alone (mapped to authenticates by CryptoBehaviorMapper) only corroborates.
        for (CryptoBehavior behavior : cryptoBehaviors) {
            if (behavior == CryptoBehavior.AUTHENTICATES) {
                continue;
            }
            result.add(behavior);
        }

        final boolean hasAuthPrimary =
                authSignals.contains(AuthContext.Kind.JWT)
                        || authSignals.contains(AuthContext.Kind.OAUTH)
                        || authSignals.contains(AuthContext.Kind.SAML)
                        || authSignals.contains(AuthContext.Kind.PRINCIPAL);
        final boolean hasTokenPrimary =
                authSignals.contains(AuthContext.Kind.JWT)
                        || authSignals.contains(AuthContext.Kind.OAUTH);
        final boolean hasPrincipal = authSignals.contains(AuthContext.Kind.PRINCIPAL);

        if (hasAuthPrimary) {
            result.add(CryptoBehavior.AUTHENTICATES);
        }
        if (hasTokenPrimary) {
            result.add(CryptoBehavior.VALIDATES_TOKEN);
        }
        if (hasPrincipal) {
            result.add(CryptoBehavior.USES_IDENTITY);
        }
        return result;
    }
}
