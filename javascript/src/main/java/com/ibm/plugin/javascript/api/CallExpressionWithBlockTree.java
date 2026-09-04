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
package com.ibm.plugin.javascript.api;

import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Call expression enriched with enclosing block context and assignment identifiers, mirroring Go's
 * {@code FunctionInvocationWIthIdentifiersTree}.
 */
public final class CallExpressionWithBlockTree implements Tree, HasLocation {

    @Nonnull private final CallExpressionTree call;
    @Nullable private final List<IdentifierTree> identifiers;
    @Nonnull private final BlockTree blockTree;

    public CallExpressionWithBlockTree(
            @Nonnull CallExpressionTree call,
            @Nullable List<IdentifierTree> identifiers,
            @Nonnull BlockTree blockTree) {
        this.call = call;
        this.identifiers = identifiers == null ? null : List.copyOf(identifiers);
        this.blockTree = blockTree;
    }

    @Nonnull
    public CallExpressionTree call() {
        return call;
    }

    @Nullable public List<IdentifierTree> identifiers() {
        return identifiers;
    }

    @Nonnull
    public BlockTree blockTree() {
        return blockTree;
    }

    @Nonnull
    public String methodName() {
        return call.methodName();
    }

    @Nonnull
    public String objectType() {
        return call.objectType();
    }

    @Nonnull
    public List<Tree> arguments() {
        return call.arguments();
    }

    @Nonnull
    @Override
    public SourceLocation location() {
        return call.location();
    }
}
