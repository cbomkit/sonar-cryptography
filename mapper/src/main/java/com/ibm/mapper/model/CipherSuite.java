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

import com.ibm.mapper.model.collections.AssetCollection;
import com.ibm.mapper.model.collections.IdentifierCollection;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nonnull;

public final class CipherSuite implements IAsset {
    @Nonnull private final Map<Class<? extends INode>, INode> children;
    @Nonnull private final DetectionLocation detectionLocation;
    @Nonnull private final Class<? extends IAsset> kind;
    @Nonnull private final String name;

    public CipherSuite(@Nonnull String name, @Nonnull DetectionLocation detectionLocation) {
        this.name = name;
        this.children = new HashMap<>();
        this.detectionLocation = detectionLocation;
        this.kind = CipherSuite.class;
    }

    public CipherSuite(
            @Nonnull String name,
            @Nonnull AssetCollection assetCollection,
            @Nonnull IdentifierCollection identifierCollection,
            @Nonnull DetectionLocation detectionLocation) {
        this.name = name;
        this.children = new HashMap<>();
        this.put(assetCollection);
        this.put(identifierCollection);
        this.detectionLocation = detectionLocation;
        this.kind = CipherSuite.class;
    }

    public CipherSuite(
            @Nonnull String name,
            @Nonnull AssetCollection assetCollection,
            @Nonnull DetectionLocation detectionLocation) {
        this.name = name;
        this.children = new HashMap<>();
        this.put(assetCollection);
        this.detectionLocation = detectionLocation;
        this.kind = CipherSuite.class;
    }

    private CipherSuite(@Nonnull CipherSuite cipherSuite) {
        this.children = new HashMap<>();
        this.detectionLocation = cipherSuite.detectionLocation;
        this.name = cipherSuite.name;
        this.kind = cipherSuite.kind;
    }

    @Nonnull
    public Optional<AssetCollection> getAssetCollection() {
        INode node = this.getChildren().get(AssetCollection.class);
        if (node == null) {
            return Optional.empty();
        }
        return Optional.of((AssetCollection) node);
    }

    @Nonnull
    public Optional<IdentifierCollection> getIdentifierCollection() {
        INode node = this.getChildren().get(IdentifierCollection.class);
        if (node == null) {
            return Optional.empty();
        }
        return Optional.of((IdentifierCollection) node);
    }

    @Nonnull
    public String getName() {
        return name;
    }

    @Override
    @Nonnull
    public Class<? extends IAsset> getKind() {
        return kind;
    }

    @Nonnull
    @Override
    public String asString() {
        return name;
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
        CipherSuite copy = new CipherSuite(this);
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
