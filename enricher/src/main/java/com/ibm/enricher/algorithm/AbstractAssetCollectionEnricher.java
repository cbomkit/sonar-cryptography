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
package com.ibm.enricher.algorithm;

import com.ibm.enricher.Enricher;
import com.ibm.enricher.IEnricher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.collections.AbstractAssetCollection;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;

public class AbstractAssetCollectionEnricher implements IEnricher {

    @Nonnull
    @Override
    public INode enrich(@Nonnull INode node) {
        if (node instanceof AbstractAssetCollection<? extends INode> collection) {
            return withEnrichedAssets(collection);
        }
        return node;
    }

    /**
     * A collection holding the enriched assets of the given one, and its children. An enricher can
     * return a new node for an asset, e.g. AES in GCM mode as authenticated encryption; an asset
     * that would change class keeps the one it has, so the collection keeps its element type.
     */
    @Nonnull
    private static <K extends INode> AbstractAssetCollection<K> withEnrichedAssets(
            @Nonnull AbstractAssetCollection<K> collection) {
        final List<K> enrichedAssets = new ArrayList<>();
        for (final K asset : collection.getCollection()) {
            final INode enriched = Enricher.enrich(List.of(asset)).iterator().next();
            enrichedAssets.add(sameClassOr(asset, enriched));
        }
        final AbstractAssetCollection<K> enrichedCollection =
                collection.createMerged(enrichedAssets);
        collection.getChildren().values().forEach(enrichedCollection::put);
        return enrichedCollection;
    }

    @Nonnull
    @SuppressWarnings("unchecked")
    private static <K extends INode> K sameClassOr(@Nonnull K asset, @Nonnull INode enriched) {
        return asset.getClass().isInstance(enriched) ? (K) enriched : asset;
    }
}
