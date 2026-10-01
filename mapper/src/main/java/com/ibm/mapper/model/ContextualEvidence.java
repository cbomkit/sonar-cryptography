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
package com.ibm.mapper.model;

import com.ibm.mapper.utils.DetectionLocation;
import java.util.Objects;
import javax.annotation.Nonnull;

/**
 * A detected contextual fact about the scanned code (e.g. an authentication interface such as JWT
 * or a servlet principal). NOT a cryptographic asset: the mapper model is the scan's intermediate
 * representation, not a crypto-asset registry. The output layer interprets this node to inform the
 * software-level behavior taxonomy and never emits it as a CBOM component. Generic by design so
 * future non-auth evidence reuses it. The {@code identifier} is a stable token (currently an {@code
 * AuthContext.Kind} name, e.g. "JWT").
 */
public final class ContextualEvidence extends Property {
    @Nonnull private final String identifier;

    public ContextualEvidence(
            @Nonnull String identifier, @Nonnull DetectionLocation detectionLocation) {
        super(ContextualEvidence.class, detectionLocation);
        this.identifier = identifier;
    }

    private ContextualEvidence(@Nonnull ContextualEvidence evidence) {
        super(evidence.type, evidence.detectionLocation, evidence.children);
        this.identifier = evidence.identifier;
    }

    @Nonnull
    public String identifier() {
        return identifier;
    }

    @Nonnull
    @Override
    public String asString() {
        return identifier;
    }

    @Nonnull
    @Override
    public INode deepCopy() {
        ContextualEvidence copy = new ContextualEvidence(this);
        for (INode child : this.children.values()) {
            copy.children.put(child.getKind(), child.deepCopy());
        }
        return copy;
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (!(object instanceof ContextualEvidence evidence)) return false;
        if (!super.equals(object)) return false;
        return Objects.equals(identifier, evidence.identifier);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), identifier);
    }
}
