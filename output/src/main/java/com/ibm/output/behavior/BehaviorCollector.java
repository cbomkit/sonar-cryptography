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
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.ContextualEvidence;
import com.ibm.mapper.model.INode;
import java.util.EnumSet;
import java.util.Set;
import javax.annotation.Nonnull;

/** Collects crypto and authentication behaviors for one scan. */
public final class BehaviorCollector {

    @Nonnull private final CryptoBehaviorMapper mapper = new CryptoBehaviorMapper();

    @Nonnull private final Set<CryptoBehavior> behaviors = EnumSet.noneOf(CryptoBehavior.class);

    public void observe(@Nonnull INode node) {
        // Add behaviors from the detected crypto asset or authentication API.
        if (node instanceof Algorithm) {
            this.behaviors.addAll(this.mapper.map(node));
        } else if (node instanceof ContextualEvidence evidence) {
            this.behaviors.addAll(authBehaviors(evidence.identifier()));
        }
    }

    /** Returns a snapshot of the behaviors collected so far. */
    @Nonnull
    public Set<CryptoBehavior> getBehaviors() {
        return Set.copyOf(this.behaviors);
    }

    @Nonnull
    private static Set<CryptoBehavior> authBehaviors(@Nonnull String identifier) {
        // Ignore evidence that does not name a known auth kind.
        final AuthContext.Kind kind;
        try {
            kind = AuthContext.Kind.valueOf(identifier);
        } catch (IllegalArgumentException ignored) {
            return Set.of();
        }

        // Map the detected auth API to its application behaviors.
        return switch (kind) {
            case JWT, OAUTH, SAML ->
                    Set.of(CryptoBehavior.AUTHENTICATES, CryptoBehavior.VALIDATES_TOKEN);
            case PRINCIPAL, MTLS ->
                    Set.of(CryptoBehavior.AUTHENTICATES, CryptoBehavior.USES_IDENTITY);
            case API_KEY -> Set.of(CryptoBehavior.AUTHENTICATES);
            case NONE -> Set.of();
        };
    }
}
