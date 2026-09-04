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

/** {@code new} expression such as {@code new tls.SecureContext(options)}. */
public final class NewExpressionTree implements Tree, HasLocation {

    @Nonnull private final String objectType;
    @Nonnull private final List<Tree> arguments;
    @Nonnull private final SourceLocation location;

    public NewExpressionTree(
            @Nonnull String objectType,
            @Nonnull List<Tree> arguments,
            @Nonnull SourceLocation location) {
        this.objectType = objectType;
        this.arguments = List.copyOf(arguments);
        this.location = location;
    }

    @Nonnull
    public String objectType() {
        return objectType;
    }

    @Nonnull
    public List<Tree> arguments() {
        return arguments;
    }

    @Nullable public String methodName() {
        return "<init>";
    }

    @Nonnull
    @Override
    public SourceLocation location() {
        return location;
    }
}
