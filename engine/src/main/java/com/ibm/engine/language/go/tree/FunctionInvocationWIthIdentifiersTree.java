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

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.sonar.go.impl.FunctionInvocationTreeImpl;
import org.sonar.plugins.go.api.BlockTree;
import org.sonar.plugins.go.api.FunctionInvocationTree;
import org.sonar.plugins.go.api.VariableDeclarationTree;

public final class FunctionInvocationWIthIdentifiersTree extends FunctionInvocationTreeImpl
        implements FunctionInvocationTree, ITreeWithBlock {
    @Nullable private final VariableDeclarationTree variableDeclarationTree;
    private final BlockTree blockTree;

    public FunctionInvocationWIthIdentifiersTree(
            @Nonnull FunctionInvocationTree functionInvocationTree,
            @Nullable VariableDeclarationTree variableDeclarationTree,
            @Nonnull BlockTree blockTree) {
        super(
                functionInvocationTree.metaData(),
                functionInvocationTree.memberSelect(),
                functionInvocationTree.arguments(),
                functionInvocationTree.returnTypes());
        this.variableDeclarationTree = variableDeclarationTree;
        this.blockTree = blockTree;
    }

    @Nullable public VariableDeclarationTree variableDeclarationTree() {
        return variableDeclarationTree;
    }

    @Override
    public @NonNull BlockTree blockTree() {
        return blockTree;
    }
}
