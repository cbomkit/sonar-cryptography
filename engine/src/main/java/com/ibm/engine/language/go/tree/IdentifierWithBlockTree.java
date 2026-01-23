/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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
import javax.annotation.Nonnull;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.sonar.go.impl.BaseTreeImpl;
import org.sonar.plugins.go.api.BlockTree;
import org.sonar.plugins.go.api.IdentifierTree;
import org.sonar.plugins.go.api.Tree;

/**
 * Wraps an IdentifierTree together with its enclosing BlockTree context.
 *
 * <p>This is used when an identifier (e.g., a variable passed as a function argument) has depending
 * detection rules that need to be resolved by searching the block for related assignments and
 * function invocations. For example, when {@code dsa.GenerateKey(privateKey, ...)} is detected, the
 * {@code privateKey} identifier needs to be traced through assignments like {@code
 * privateKey.Parameters = *params} to find the originating {@code dsa.GenerateParameters(...)}
 * call.
 */
public final class IdentifierWithBlockTree extends BaseTreeImpl implements ITreeWithBlock {
    @Nonnull private final IdentifierTree identifierTree;
    @Nonnull private final BlockTree blockTree;

    public IdentifierWithBlockTree(
            @Nonnull IdentifierTree identifierTree, @Nonnull BlockTree blockTree) {
        super(identifierTree.metaData());
        this.identifierTree = identifierTree;
        this.blockTree = blockTree;
    }

    @Nonnull
    public IdentifierTree identifierTree() {
        return identifierTree;
    }

    @Override
    public @NonNull BlockTree blockTree() {
        return blockTree;
    }

    @Override
    public List<Tree> children() {
        return identifierTree.children();
    }
}
