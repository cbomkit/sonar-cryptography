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
 * Base interface for the JavaScript/TypeScript nodes the detection engine works on.
 *
 * <p>Implementations are produced by {@code JavaScriptTreeConverter} from the ANTLR4 parse tree and
 * expose only what the engine needs, which keeps the engine free of ANTLR types.
 */
public interface JavaScriptTree {

    /** Returns the 1-based line number of this node in the source file. */
    int getLine();

    /** Returns the 0-based character offset within the line. */
    int getColumn();

    /** Returns a brief human-readable description of this node. */
    @Nonnull
    String getText();

    /** Returns the lexical scope this node was created in, when it needs one to resolve names. */
    @Nullable default JavaScriptScope getScope() {
        return null;
    }
}
