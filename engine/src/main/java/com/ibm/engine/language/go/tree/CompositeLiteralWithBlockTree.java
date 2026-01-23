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
package com.ibm.engine.language.go.tree;

import java.util.List;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.sonar.go.impl.BaseTreeImpl;
import org.sonar.plugins.go.api.BlockTree;
import org.sonar.plugins.go.api.CompositeLiteralTree;
import org.sonar.plugins.go.api.IdentifierTree;
import org.sonar.plugins.go.api.KeyValueTree;
import org.sonar.plugins.go.api.Tree;

/**
 * Wraps a CompositeLiteralTree together with its enclosing BlockTree context and optional variable
 * identifiers.
 *
 * <p>This is used when a composite literal (e.g., {@code tls.Config{MinVersion: tls.VersionTLS12}})
 * is detected and needs to be analyzed for its key-value fields. The detection engine treats
 * composite literals similar to constructor calls, where the field names (keys) act as named
 * parameters.
 */
public final class CompositeLiteralWithBlockTree extends BaseTreeImpl implements ITreeWithBlock {
    @Nonnull private final CompositeLiteralTree compositeLiteralTree;
    @Nonnull private final List<IdentifierTree> identifiers;
    @Nonnull private final BlockTree blockTree;

    public CompositeLiteralWithBlockTree(
            @Nonnull CompositeLiteralTree compositeLiteralTree,
            @Nullable List<IdentifierTree> identifiers,
            @Nonnull BlockTree blockTree) {
        super(compositeLiteralTree.metaData());
        this.compositeLiteralTree = compositeLiteralTree;
        this.identifiers = identifiers != null ? identifiers : List.of();
        this.blockTree = blockTree;
    }

    @Nonnull
    public CompositeLiteralTree compositeLiteralTree() {
        return compositeLiteralTree;
    }

    @Nonnull
    public List<IdentifierTree> identifiers() {
        return identifiers;
    }

    @Override
    public @NonNull BlockTree blockTree() {
        return blockTree;
    }

    @Nonnull
    public Tree type() {
        return compositeLiteralTree.type();
    }

    @Nonnull
    public List<Tree> elements() {
        return compositeLiteralTree.elements();
    }

    @Nonnull
    public Stream<KeyValueTree> getKeyValuesElements() {
        return compositeLiteralTree.getKeyValuesElements();
    }

    public boolean hasType(@Nonnull String packageName, @Nonnull String typeName) {
        return compositeLiteralTree.hasType(packageName, typeName);
    }

    @Override
    public List<Tree> children() {
        return compositeLiteralTree.children();
    }
}
