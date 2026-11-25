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
package com.ibm.plugin.javascript.language;

import javax.annotation.Nonnull;

/**
 * Minimal symbol for JavaScript detection: the identifier a created object was assigned to, plus
 * the line of that assignment. The line lets {@code
 * JavaScriptDetectionEngine#isInvocationOnVariable} refuse a call that textually precedes the
 * creation it is supposedly a member of.
 */
public final class JavaScriptSymbol {

    @Nonnull private final String name;
    private final int declarationLine;

    public JavaScriptSymbol(@Nonnull String name, int declarationLine) {
        this.name = name;
        this.declarationLine = declarationLine;
    }

    @Nonnull
    public String getName() {
        return name;
    }

    public int getDeclarationLine() {
        return declarationLine;
    }

    @Override
    public String toString() {
        return "JavaScriptSymbol{" + name + "@" + declarationLine + "}";
    }
}
