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
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nonnull;

public class Algorithm implements IAlgorithm, Cloneable {
    @Nonnull protected Map<Class<? extends INode>, INode> children;
    @Nonnull protected final Class<? extends IPrimitive> kind;
    @Nonnull protected final DetectionLocation detectionLocation;
    @Nonnull protected final String name;
    @Nonnull protected final NodeOrigin origin;

    public Algorithm(
            @Nonnull IAlgorithm algorithm, @Nonnull final Class<? extends IPrimitive> asKind) {
        this.name = algorithm.getName();
        this.children = new HashMap<>(algorithm.getChildren());
        this.detectionLocation = algorithm.getDetectionContext();
        this.kind = asKind;
        this.origin = algorithm.getOrigin();
    }

    public Algorithm(
            @Nonnull String name,
            @Nonnull final Class<? extends IPrimitive> asKind,
            @Nonnull DetectionLocation detectionLocation) {
        this(name, asKind, detectionLocation, NodeOrigin.DETECTED);
    }

    public Algorithm(
            @Nonnull String name,
            @Nonnull final Class<? extends IPrimitive> asKind,
            @Nonnull DetectionLocation detectionLocation,
            @Nonnull NodeOrigin origin) {
        this.name = name;
        this.children = new HashMap<>();
        this.detectionLocation = detectionLocation;
        this.kind = asKind;
        this.origin = origin;
    }

    /** A copy of the given algorithm without its children. */
    protected Algorithm(@Nonnull Algorithm algorithm) {
        this.children = new HashMap<>();
        this.kind = algorithm.kind;
        this.detectionLocation = algorithm.detectionLocation;
        this.name = algorithm.name;
        this.origin = algorithm.origin;
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (!(object instanceof Algorithm algorithm)) return false;
        return Objects.equals(kind, algorithm.kind)
                && Objects.equals(detectionLocation, algorithm.detectionLocation)
                && Objects.equals(name, algorithm.name);
    }

    @Override
    public int hashCode() {
        return Objects.hash(kind, detectionLocation, name);
    }

    @Nonnull
    public String getName() {
        return name;
    }

    @Nonnull
    public Class<? extends IPrimitive> getKind() {
        return kind;
    }

    @Nonnull
    @Override
    public String asString() {
        return getName();
    }

    /**
     * Composes this algorithm's name as {@code base[-keyLength][-mode][-padding]} following the
     * CycloneDX pattern format (https://cyclonedx.org/registry/cryptography/#pattern-format). Only
     * the parameters flagged {@code true} — and only when present as children — are appended.
     */
    @Nonnull
    protected String composeName(boolean keyLength, boolean mode, boolean padding) {
        final StringBuilder sb = new StringBuilder(this.name);
        if (keyLength) {
            this.hasChildOfType(KeyLength.class)
                    .ifPresent(k -> sb.append("-").append(k.asString()));
        }
        if (mode) {
            this.hasChildOfType(Mode.class).ifPresent(m -> sb.append("-").append(m.asString()));
        }
        if (padding) {
            this.hasChildOfType(Padding.class).ifPresent(p -> sb.append("-").append(p.asString()));
        }
        return sb.toString();
    }

    @Nonnull
    @Override
    public DetectionLocation getDetectionContext() {
        return detectionLocation;
    }

    @Nonnull
    @Override
    public NodeOrigin getOrigin() {
        return origin;
    }

    @Nonnull
    @Override
    public Optional<INode> hasChildOfType(@Nonnull Class<? extends INode> nodeType) {
        return Optional.ofNullable(children.get(nodeType));
    }

    @Override
    public void removeChildOfType(@Nonnull Class<? extends INode> nodeType) {
        this.children.remove(nodeType);
    }

    /**
     * Subclasses with mutable fields outside {@code children} must copy those fields themselves.
     */
    @Nonnull
    @Override
    public INode deepCopy() {
        final Algorithm copy = copy();
        for (INode child : this.children.values()) {
            copy.children.put(child.getKind(), child.deepCopy());
        }
        return copy;
    }

    /**
     * A copy of this algorithm without its children. An algorithm class returns an instance of its
     * own class, which gives the composed name of the algorithm, how the enrichers complete it and
     * how the output reports it.
     */
    @Nonnull
    protected Algorithm copy() {
        return new Algorithm(this);
    }

    /**
     * This algorithm as another kind, e.g. a block cipher used as a MAC: a node of the class of
     * this algorithm with its name, detection location and origin, that shares its children. It
     * takes the place of this algorithm. An algorithm class returns an instance of its own class,
     * which gives the composed name of the algorithm (e.g. {@code AES-128-GMAC}), how the enrichers
     * complete it and how the output reports it.
     */
    @Nonnull
    public Algorithm asKind(@Nonnull Class<? extends IPrimitive> kind) {
        return new Algorithm(this, kind);
    }

    public boolean is(@Nonnull final Class<? extends INode> type) {
        return this.getKind().equals(type);
    }

    @Override
    public void put(@Nonnull INode child) {
        this.children.put(child.getKind(), child);
    }

    @Override
    public boolean hasChildren() {
        return !this.children.isEmpty();
    }

    @Nonnull
    @Override
    public Map<Class<? extends INode>, INode> getChildren() {
        return this.children;
    }

    @Override
    public String toString() {
        return name;
    }
}
