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

import java.util.Collections;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

/** Block of statements (typically a file's extracted call expressions). */
public final class BlockTree implements Tree {

    @Nonnull private final List<Tree> statements;
    @Nonnull private final Map<String, String> bindings;
    @Nonnull private final Map<String, String> variableValues;

    public BlockTree(@Nonnull List<Tree> statements) {
        this(statements, Collections.emptyMap(), Collections.emptyMap());
    }

    public BlockTree(
            @Nonnull List<Tree> statements,
            @Nonnull Map<String, String> bindings,
            @Nonnull Map<String, String> variableValues) {
        this.statements = List.copyOf(statements);
        this.bindings = Map.copyOf(bindings);
        this.variableValues = Map.copyOf(variableValues);
    }

    @Nonnull
    public List<Tree> statements() {
        return statements;
    }

    /** Module bindings from require/import (identifier → crypto/tls module). */
    @Nonnull
    public Map<String, String> bindings() {
        return bindings;
    }

    /** String literal values assigned to variables in the same file. */
    @Nonnull
    public Map<String, String> variableValues() {
        return variableValues;
    }
}
