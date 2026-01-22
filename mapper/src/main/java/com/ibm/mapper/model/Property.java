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

public abstract class Property implements IProperty {
    @Nonnull protected final Class<? extends IProperty> type;
    @Nonnull protected final Map<Class<? extends INode>, INode> children;
    @Nonnull protected final DetectionLocation detectionLocation;
    @Nonnull protected final NodeOrigin origin;

    protected Property(
            @Nonnull Class<? extends IProperty> type,
            @Nonnull DetectionLocation detectionLocation) {
        this(type, detectionLocation, NodeOrigin.DETECTED);
    }

    protected Property(
            @Nonnull Class<? extends IProperty> type,
            @Nonnull DetectionLocation detectionLocation,
            @Nonnull NodeOrigin origin) {
        this.type = type;
        this.children = new HashMap<>();
        this.detectionLocation = detectionLocation;
        this.origin = origin;
    }

    protected Property(
            @Nonnull Class<? extends IProperty> type,
            @Nonnull DetectionLocation detectionLocation,
            @Nonnull Map<Class<? extends INode>, INode> children) {
        this(type, detectionLocation, children, NodeOrigin.DETECTED);
    }

    protected Property(
            @Nonnull Class<? extends IProperty> type,
            @Nonnull DetectionLocation detectionLocation,
            @Nonnull Map<Class<? extends INode>, INode> children,
            @Nonnull NodeOrigin origin) {
        this.type = type;
        this.children = children;
        this.detectionLocation = detectionLocation;
        this.origin = origin;
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
    public Class<? extends INode> getKind() {
        return this.type;
    }

    @Nonnull
    @Override
    public Map<Class<? extends INode>, INode> getChildren() {
        return this.children;
    }

    @Override
    public boolean is(@Nonnull Class<? extends INode> type) {
        return type.equals(this.type);
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

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (!(object instanceof Property property)) return false;
        return Objects.equals(type, property.type)
                && Objects.equals(detectionLocation, property.detectionLocation);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, detectionLocation);
    }
}
