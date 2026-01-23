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
import com.ibm.mapper.model.Identifier;
import java.util.List;
import javax.annotation.Nonnull;

public class IdentifierCollection extends AbstractAssetCollection<Identifier> {

    public IdentifierCollection(@Nonnull List<Identifier> collection) {
        super(collection, IdentifierCollection.class);
    }

    private IdentifierCollection(@Nonnull IdentifierCollection identifierCollection) {
        super(identifierCollection.collection, identifierCollection.kind);
    }

    @Nonnull
    @Override
    public INode deepCopy() {
        IdentifierCollection copy = new IdentifierCollection(this);
        for (INode child : this.children.values()) {
            copy.children.put(child.getKind(), child.deepCopy());
        }
        return copy;
    }

    @Nonnull
    @Override
    public IdentifierCollection createMerged(@Nonnull List<Identifier> mergedCollection) {
        return new IdentifierCollection(mergedCollection);
    }
}
