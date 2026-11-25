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

import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * A lightweight, syntactic symbol table for one lexical scope (module, function body or nested
 * block). Scopes chain through {@link #getParent()}; lookups walk outwards like JavaScript name
 * resolution does for the subset modelled here.
 */
public final class JavaScriptScope {

    @Nullable private final JavaScriptScope parent;
    @Nonnull private final Map<String, JavaScriptVariable> variables = new HashMap<>();

    public JavaScriptScope(@Nullable JavaScriptScope parent) {
        this.parent = parent;
    }

    /** Declares a variable here; a repeated declaration is merged so conflicts are detected. */
    public void define(@Nonnull String name, @Nonnull JavaScriptVariable variable) {
        JavaScriptVariable existing = variables.get(name);
        if (existing != null) {
            variables.put(name, existing.withAdditionalAssignment(variable.initializer()));
        } else {
            variables.put(name, variable);
        }
    }

    /** Records {@code name = value;} on the scope that declares {@code name}, if any. */
    public void recordAssignment(@Nonnull String name, @Nullable JavaScriptTree newValue) {
        JavaScriptScope owner = findOwner(name);
        if (owner == null) {
            return;
        }
        owner.variables.put(name, owner.variables.get(name).withAdditionalAssignment(newValue));
    }

    @Nullable public JavaScriptVariable lookup(@Nonnull String name) {
        JavaScriptScope owner = findOwner(name);
        return owner == null ? null : owner.variables.get(name);
    }

    @Nullable private JavaScriptScope findOwner(@Nonnull String name) {
        JavaScriptScope current = this;
        while (current != null) {
            if (current.variables.containsKey(name)) {
                return current;
            }
            current = current.parent;
        }
        return null;
    }

    @Nullable public JavaScriptScope getParent() {
        return parent;
    }
}
