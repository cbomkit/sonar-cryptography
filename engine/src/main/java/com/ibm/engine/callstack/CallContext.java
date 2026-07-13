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
package com.ibm.engine.callstack;

import com.ibm.engine.language.IScanContext;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * A recorded call site accumulated by the {@link CallStackAgent} for later cross-file hook
 * matching.
 *
 * <p>{@link RetainedCall} keeps the live AST tree (today's behavior); {@link DetachedCall} holds a
 * tree-free snapshot so the file's AST can be garbage-collected after analysis.
 */
public sealed interface CallContext<R, T> permits RetainedCall, DetachedCall {

    /** The recorded call tree, or {@code null} for a detached record that holds no AST. */
    @Nullable T tree();

    /** The scan context of the file the call was recorded in. */
    @Nonnull
    IScanContext<R, T> publisher();
}
