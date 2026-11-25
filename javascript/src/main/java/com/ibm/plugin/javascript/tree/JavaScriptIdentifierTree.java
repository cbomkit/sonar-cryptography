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
package com.ibm.plugin.javascript.tree;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/** A reference to a named binding, resolved later through its {@link JavaScriptScope}. */
public final class JavaScriptIdentifierTree implements JavaScriptTree {

    private final int line;
    private final int column;
    @Nonnull private final String name;
    @Nullable private final JavaScriptScope scope;

    public JavaScriptIdentifierTree(
            int line, int column, @Nonnull String name, @Nullable JavaScriptScope scope) {
        this.line = line;
        this.column = column;
        this.name = name;
        this.scope = scope;
    }

    @Override
    public int getLine() {
        return line;
    }

    @Override
    public int getColumn() {
        return column;
    }

    @Nonnull
    @Override
    public String getText() {
        return name;
    }

    @Nonnull
    public String getName() {
        return name;
    }

    @Nullable @Override
    public JavaScriptScope getScope() {
        return scope;
    }
}
