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

/**
 * This is a special collection of INode: when multiple {@code MergeableCollection} are appended to
 * a parent node, they get merged (only one {@code MergeableCollection} is actually appended,
 * containing the merged collection and the merged list of children).
 *
 * <p>This differs from the default behavior, in which the root nodes are duplicated to create
 * multiple trees, each containing one instance of the various {@code MergeableCollection}.
 */
// TODO: handle this in the output layer
public class MergeableCollection extends AbstractAssetCollection<INode> {

    public MergeableCollection(@Nonnull List<INode> collection) {
        super(collection, MergeableCollection.class);
    }

    private MergeableCollection(@Nonnull MergeableCollection mergeableCollection) {
        super(mergeableCollection.collection, mergeableCollection.kind);
    }

    @Nonnull
    @Override
    public INode deepCopy() {
        MergeableCollection copy = new MergeableCollection(this);
        for (INode child : this.children.values()) {
            copy.children.put(child.getKind(), child.deepCopy());
        }
        return copy;
    }

    @Override
    public boolean isMergeable() {
        return true;
    }

    @Nonnull
    @Override
    public MergeableCollection createMerged(@Nonnull List<INode> mergedCollection) {
        return new MergeableCollection(mergedCollection);
    }
}
