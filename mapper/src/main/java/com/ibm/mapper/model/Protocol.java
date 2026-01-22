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
import java.util.Optional;
import javax.annotation.Nonnull;

public class Protocol implements IAsset {
    @Nonnull protected final Map<Class<? extends INode>, INode> children;
    @Nonnull protected final Class<? extends Protocol> kind;
    @Nonnull protected final DetectionLocation detectionLocation;
    @Nonnull protected final String type;

    public Protocol(@Nonnull Protocol protocol, @Nonnull final Class<? extends Protocol> asKind) {
        this.type = protocol.type;
        this.children = protocol.getChildren();
        this.detectionLocation = protocol.detectionLocation;
        this.kind = asKind;
    }

    public Protocol(@Nonnull String type, @Nonnull DetectionLocation detectionLocation) {
        this.type = type;
        this.children = new HashMap<>();
        this.detectionLocation = detectionLocation;
        this.kind = Protocol.class;
    }

    private Protocol(@Nonnull Protocol protocol) {
        this.children = new HashMap<>();
        this.kind = protocol.kind;
        this.detectionLocation = protocol.detectionLocation;
        this.type = protocol.type;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Protocol protocol)) return false;

        return kind.equals(protocol.kind)
                && detectionLocation.equals(protocol.detectionLocation)
                && type.equals(protocol.type);
    }

    @Override
    public int hashCode() {
        int result = kind.hashCode();
        result = 31 * result + detectionLocation.hashCode();
        result = 31 * result + type.hashCode();
        return result;
    }

    @Override
    @Nonnull
    public Map<Class<? extends INode>, INode> getChildren() {
        return children;
    }

    @Override
    @Nonnull
    public Class<? extends Protocol> getKind() {
        return kind;
    }

    @Nonnull
    @Override
    public String asString() {
        return type;
    }

    @Nonnull
    @Override
    public DetectionLocation getDetectionContext() {
        return detectionLocation;
    }

    @Nonnull
    @Override
    public NodeOrigin getOrigin() {
        return NodeOrigin.DETECTED;
    }

    @Nonnull
    public String getType() {
        return type;
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

    @Nonnull
    @Override
    public INode deepCopy() {
        Protocol copy = new Protocol(this);
        for (INode child : this.children.values()) {
            copy.children.put(child.getKind(), child.deepCopy());
        }
        return copy;
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

    @Override
    public String toString() {
        return type;
    }
}
