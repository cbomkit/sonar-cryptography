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
import com.ibm.output.behavior.rules.AuthInterfaceRule;
import com.ibm.output.behavior.rules.CryptoBehaviorRule;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import javax.annotation.Nonnull;

/**
 * The output layer's single entry point to the behavior subsystem. Feed every processed node to
 * {@link #observe(INode)} during collection; call {@link #inferBehaviors()} once at emission time
 * to run the rule registry over the collected {@link BehaviorSignals}. Total: unrecognized nodes
 * and identifiers are ignored, never errors.
 */
public final class BehaviorCollector {

    private static final List<IBehaviorRule> RULES =
            List.of(new CryptoBehaviorRule(), new AuthInterfaceRule());

    @Nonnull private final CryptoBehaviorMapper mapper = new CryptoBehaviorMapper();

    @Nonnull
    private final Set<CryptoBehavior> cryptoBehaviors = EnumSet.noneOf(CryptoBehavior.class);

    @Nonnull private final Set<AuthContext.Kind> authKinds = EnumSet.noneOf(AuthContext.Kind.class);

    public void observe(@Nonnull INode node) {
        if (node instanceof Algorithm) {
            this.cryptoBehaviors.addAll(this.mapper.map(node));
        } else if (node instanceof ContextualEvidence evidence) {
            // ContextualEvidence carries a generic identifier; only the ones naming an
            // auth-interface kind are behavior signals. Unknown identifiers are skipped.
            try {
                this.authKinds.add(AuthContext.Kind.valueOf(evidence.identifier()));
            } catch (IllegalArgumentException ignored) {
                // not an auth-interface evidence identifier we model
            }
        }
    }

    @Nonnull
    public Set<CryptoBehavior> inferBehaviors() {
        final BehaviorSignals signals = new BehaviorSignals(this.cryptoBehaviors, this.authKinds);
        final Set<CryptoBehavior> result = EnumSet.noneOf(CryptoBehavior.class);
        for (IBehaviorRule rule : RULES) {
            result.addAll(rule.apply(signals));
        }
        return result;
    }
}
