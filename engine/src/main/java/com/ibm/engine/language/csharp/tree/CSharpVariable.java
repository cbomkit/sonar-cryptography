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

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * A single declared C# symbol tracked by {@link CSharpScope}: a local variable, a {@code const}
 * declaration, a method parameter, or a class-level {@code const} field.
 *
 * <p>This is intentionally minimal — there is no full semantic model behind it (no inheritance, no
 * overload resolution). It exists purely to answer two questions safely: "does a value definitely
 * resolve to a single, known expression?" and "what is this identifier's declared type?".
 *
 * <p><b>Multiple assignment tracking:</b> {@link #assignmentCount()} lets {@code
 * CSharpDetectionEngine} refuse to resolve a value when a local variable is reassigned more than
 * once with differing values (see the class javadoc of {@code CSharpDetectionEngine} guard G4) —
 * consistent with the project-wide principle that no value is better than a wrong one. A {@link
 * Kind#CONST} or {@link Kind#PARAMETER} variable is never reassigned, so its count is always
 * exactly {@code 1} (const) or {@code 0} (parameter, no local initializer).
 */
public record CSharpVariable(
        @Nonnull String name,
        @Nullable String declaredType,
        @Nullable CSharpTree initializer,
        int assignmentCount,
        @Nonnull Kind kind,
        int line) {

    /** What kind of declaration this variable came from. */
    public enum Kind {
        /** A {@code var x = ...} or {@code Type x = ...} local variable declaration. */
        LOCAL,
        /**
         * A {@code const Type x = ...} local constant declaration, or a class-level const field.
         */
        CONST,
        /**
         * A class-level field with an initializer that is not {@code const}. Registered with a
         * conflicting assignment count when the class assigns to it elsewhere, so the engine's G4
         * guard then refuses to resolve it.
         */
        FIELD,
        /** A method/lambda/local-function formal parameter — value is never known locally. */
        PARAMETER
    }

    /**
     * Returns a copy of this variable with its assignment count incremented and, if the newly
     * observed value differs from the current one, its initializer cleared (so a later lookup finds
     * no single resolvable value — see guard G4).
     */
    @Nonnull
    public CSharpVariable withAdditionalAssignment(@Nullable CSharpTree newValue) {
        boolean sameValue =
                initializer != null
                        && newValue != null
                        && initializer.getText().equals(newValue.getText());
        return new CSharpVariable(
                name,
                declaredType,
                sameValue ? initializer : null,
                assignmentCount + 1,
                kind,
                line);
    }
}
