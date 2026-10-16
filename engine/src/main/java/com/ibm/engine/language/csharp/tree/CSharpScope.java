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
package com.ibm.engine.language.csharp.tree;

import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * A lightweight, syntactic symbol table for a single C# lexical scope (a class body, a method body,
 * or a nested control-flow block within one).
 *
 * <p>Scopes form a chain via {@link #parent}: looking up a name walks from the innermost scope
 * outward, which is exactly how C# name resolution and shadowing work for the subset this class
 * models (locals, {@code const}s, and parameters — see {@link CSharpVariable}).
 *
 * <p>This is deliberately not a real compiler symbol table: there is no notion of a variable's
 * lifetime ending at a particular statement (a lookup from anywhere in a scope can see any variable
 * declared earlier in it or in an ancestor scope), and there is no cross-file or inheritance-aware
 * resolution. It exists only to let {@code CSharpDetectionEngine} answer "is this identifier backed
 * by exactly one known value?" without ever guessing.
 */
public final class CSharpScope {

    @Nullable private final CSharpScope parent;
    @Nonnull private final Map<String, CSharpVariable> variables = new HashMap<>();

    public CSharpScope(@Nullable CSharpScope parent) {
        this.parent = parent;
    }

    /**
     * Declares a variable in this scope. If a variable with the same name already exists in this
     * exact scope (a reassignment, e.g. {@code x = 1; x = 2;}, or a shadowing re-declaration is not
     * possible in the same scope in C# but a plain assignment is), it is merged via {@link
     * CSharpVariable#withAdditionalAssignment} so that conflicting values are detected.
     */
    public void define(@Nonnull String name, @Nonnull CSharpVariable variable) {
        CSharpVariable existing = variables.get(name);
        if (existing != null) {
            variables.put(name, existing.withAdditionalAssignment(variable.initializer()));
        } else {
            variables.put(name, variable);
        }
    }

    /**
     * Replaces an already-declared variable outright, in the scope that declares it.
     *
     * <p>Unlike {@link #define}, this does not merge with what is already there — it is for the
     * case where a variable's value becomes known only after the declaration was recorded, namely a
     * formal parameter resolved from its method's call sites (see {@code
     * CSharpTreeConverter#resolveParametersFromCallSites}). Merging would be wrong there: the
     * placeholder entry has no value, so a merge would conclude the two disagree and discard both.
     */
    public void replace(@Nonnull String name, @Nonnull CSharpVariable variable) {
        CSharpScope owner = findOwner(name);
        (owner == null ? this : owner).variables.put(name, variable);
    }

    /**
     * Records an additional assignment to an already-declared variable (e.g. {@code x = <expr>;}
     * with no {@code var}/type prefix). Does nothing if {@code name} is not declared anywhere in
     * this scope chain — we never invent a variable from a bare assignment, since its declared type
     * would be unknown.
     */
    public void recordAssignment(@Nonnull String name, @Nullable CSharpTree newValue) {
        CSharpScope owner = findOwner(name);
        if (owner == null) {
            return;
        }
        CSharpVariable existing = owner.variables.get(name);
        owner.variables.put(name, existing.withAdditionalAssignment(newValue));
    }

    /** Looks up {@code name} in this scope, then walks up the parent chain. */
    @Nullable public CSharpVariable lookup(@Nonnull String name) {
        CSharpScope owner = findOwner(name);
        return owner == null ? null : owner.variables.get(name);
    }

    @Nullable private CSharpScope findOwner(@Nonnull String name) {
        CSharpScope current = this;
        while (current != null) {
            if (current.variables.containsKey(name)) {
                return current;
            }
            current = current.parent;
        }
        return null;
    }

    @Nullable public CSharpScope getParent() {
        return parent;
    }
}
