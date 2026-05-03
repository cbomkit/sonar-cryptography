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
package com.ibm.enricher;

import com.ibm.enricher.algorithm.AESEnricher;
import com.ibm.enricher.algorithm.AbstractAssetCollectionEnricher;
import com.ibm.enricher.algorithm.DESEnricher;
import com.ibm.enricher.algorithm.DHEnricher;
import com.ibm.enricher.algorithm.DSAEnricher;
import com.ibm.enricher.algorithm.HMACEnricher;
import com.ibm.enricher.algorithm.KEMEnricher;
import com.ibm.enricher.algorithm.PBES1Enricher;
import com.ibm.enricher.algorithm.PBKDF2Enricher;
import com.ibm.enricher.algorithm.RSAEnricher;
import com.ibm.enricher.algorithm.RSAoaepEnricher;
import com.ibm.enricher.algorithm.RSAssaPSSEnricher;
import com.ibm.enricher.algorithm.SHA2Enricher;
import com.ibm.enricher.algorithm.SHA3Enricher;
import com.ibm.enricher.algorithm.SignatureEnricher;
import com.ibm.enricher.algorithm.TagOrDigestEnricher;
import com.ibm.enricher.key.SecretKeyEnricher;
import com.ibm.mapper.model.INode;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * This enricher instance operates on a language-agnostic level, meaning it will enrich the given
 * list of nodes with general cryptographic knowledge, such as OIDs. This does not include
 * language-specific information like default key sizes. Therefore, create a library-specific
 * enricher instance as part of the language package.
 */
public class Enricher implements IEnricher {
    /**
     * Enriches a list of nodes with additional information.
     *
     * @param nodes The list of nodes to enrich
     */
    @Nonnull
    public static Collection<INode> enrich(@Nonnull final Collection<INode> nodes) {
        return nodes.stream().map(Enricher::enrichTree).toList();
    }

    @Nonnull
    private static INode enrichTree(@Nonnull INode node) {
        final Enricher enricher = new Enricher();
        final INode enriched = enricher.enrich(node);

        final Collection<INode> enrichedChildren = new ArrayList<>();
        final Collection<INode> markForRemoval = new ArrayList<>();
        for (final INode child : enriched.getChildren().values()) {
            final INode enrichedChild = enrichTree(child);
            if (!child.is(enrichedChild.getKind())) {
                markForRemoval.add(child);
            }
            enrichedChildren.add(enrichedChild);
        }

        enrichedChildren.forEach(enriched::put);
        markForRemoval.forEach(remove -> enriched.removeChildOfType(remove.getKind()));
        return enriched;
    }

    @Nonnull
    private static final List<IEnricher> enrichers =
            List.of(
                    new AESEnricher(),
                    new DESEnricher(),
                    new RSAEnricher(),
                    new DHEnricher(),
                    new DSAEnricher(),
                    new SHA2Enricher(),
                    new SHA3Enricher(),
                    new HMACEnricher(),
                    new PBKDF2Enricher(),
                    new PBES1Enricher(),
                    new RSAssaPSSEnricher(),
                    new RSAoaepEnricher(),
                    new SignatureEnricher(),
                    new TagOrDigestEnricher(),
                    new KEMEnricher(),
                    new SecretKeyEnricher(),
                    new AbstractAssetCollectionEnricher());

    /**
     * Enriches the given node with additional information.
     *
     * @param node The node to enrich
     */
    @Nonnull
    @Override
    public INode enrich(@Nonnull INode node) {
        for (final IEnricher enricher : enrichers) {
            node = enricher.enrich(node);
        }
        return node;
    }
}
