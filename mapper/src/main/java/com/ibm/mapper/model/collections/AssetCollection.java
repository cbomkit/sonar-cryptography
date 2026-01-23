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
package com.ibm.mapper.model.collections;

import com.ibm.mapper.model.INode;
import java.util.List;
import javax.annotation.Nonnull;

public class AssetCollection extends AbstractAssetCollection<INode> {

    public AssetCollection(@Nonnull List<INode> collection) {
        super(collection, AssetCollection.class);
    }

    private AssetCollection(@Nonnull AssetCollection assetCollection) {
        super(assetCollection.collection, assetCollection.kind);
    }

    @Nonnull
    @Override
    public INode deepCopy() {
        AssetCollection copy = new AssetCollection(this);
        for (INode child : this.children.values()) {
            copy.children.put(child.getKind(), child.deepCopy());
        }
        return copy;
    }

    @Nonnull
    @Override
    public AssetCollection createMerged(@Nonnull List<INode> mergedCollection) {
        return new AssetCollection(mergedCollection);
    }
}
