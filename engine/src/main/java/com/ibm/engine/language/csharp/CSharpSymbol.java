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
package com.ibm.engine.language.csharp;

import javax.annotation.Nonnull;

/**
 * Minimal symbol representation for C# detection.
 *
 * <p>Since the ANTLR4 grammar does not provide semantic symbol resolution (no type inference), this
 * class holds only the identifier name plus the source line where it was created (the line of the
 * {@code var x = ...}/{@code x = ...} statement that produced the tracked value). The declaration
 * line lets {@code CSharpDetectionEngine#isInvocationOnVariable} refuse to match a call that
 * textually precedes the creation it is supposedly a member of — see that method's guard against
 * matching {@code x.Foo()} written before {@code var x = ...} in the same (flattened) block.
 */
public final class CSharpSymbol {

    @Nonnull private final String name;
    private final int declarationLine;

    public CSharpSymbol(@Nonnull String name, int declarationLine) {
        this.name = name;
        this.declarationLine = declarationLine;
    }

    @Nonnull
    public String getName() {
        return name;
    }

    /** The line of the statement that assigned this symbol's tracked value. */
    public int getDeclarationLine() {
        return declarationLine;
    }

    @Override
    public String toString() {
        return "CSharpSymbol{" + name + "@" + declarationLine + "}";
    }
}
