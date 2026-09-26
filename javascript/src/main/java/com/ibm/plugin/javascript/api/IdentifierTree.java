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
import javax.annotation.Nullable;

/** Identifier node (variable or property name). */
public final class IdentifierTree implements Tree, HasLocation {

    @Nonnull private final String name;
    @Nullable private final String resolvedModule;
    @Nonnull private final SourceLocation location;

    public IdentifierTree(
            @Nonnull String name,
            @Nullable String resolvedModule,
            @Nonnull SourceLocation location) {
        this.name = name;
        this.resolvedModule = resolvedModule;
        this.location = location;
    }

    @Nonnull
    public String name() {
        return name;
    }

    /** Resolved module path when this identifier is a crypto/tls import alias. */
    @Nullable public String resolvedModule() {
        return resolvedModule;
    }

    @Nonnull
    @Override
    public SourceLocation location() {
        return location;
    }
}
