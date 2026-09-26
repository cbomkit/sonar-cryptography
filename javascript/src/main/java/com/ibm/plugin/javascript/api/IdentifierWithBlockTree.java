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

import javax.annotation.Nonnull;

/**
 * Identifier with enclosing block context, used when a depending parameter is a variable reference
 * within the same scope.
 */
public final class IdentifierWithBlockTree implements Tree, HasLocation {

    @Nonnull private final IdentifierTree identifier;
    @Nonnull private final BlockTree blockTree;

    public IdentifierWithBlockTree(
            @Nonnull IdentifierTree identifier, @Nonnull BlockTree blockTree) {
        this.identifier = identifier;
        this.blockTree = blockTree;
    }

    @Nonnull
    public IdentifierTree identifier() {
        return identifier;
    }

    @Nonnull
    public BlockTree blockTree() {
        return blockTree;
    }

    @Nonnull
    @Override
    public SourceLocation location() {
        return identifier.location();
    }
}
