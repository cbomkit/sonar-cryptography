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

/**
 * A declared symbol tracked by {@link JavaScriptScope}: a {@code const}/{@code let}/{@code var}
 * binding or a function parameter.
 *
 * <p>Mirrors {@code CSharpVariable}: {@link #assignmentCount()} lets the engine refuse to resolve a
 * variable that was assigned more than once with differing values ("no value is better than a wrong
 * one").
 */
public record JavaScriptVariable(
        @Nonnull String name,
        @Nullable JavaScriptTree initializer,
        int assignmentCount,
        @Nonnull Kind kind,
        int line) {

    /** What kind of declaration this variable came from. */
    public enum Kind {
        /** {@code const x = ...} */
        CONST,
        /** {@code let x = ...} or {@code var x = ...} */
        MUTABLE,
        /** A formal parameter; its value is never known locally. */
        PARAMETER,
        /** A compiler-introduced name for an intermediate result of a call chain. */
        CHAIN
    }

    /** Copy with one more assignment; the initializer is cleared when the new value differs. */
    @Nonnull
    public JavaScriptVariable withAdditionalAssignment(@Nullable JavaScriptTree newValue) {
        boolean sameValue =
                initializer != null
                        && newValue != null
                        && initializer.getText().equals(newValue.getText());
        return new JavaScriptVariable(
                name, sameValue ? initializer : null, assignmentCount + 1, kind, line);
    }
}
