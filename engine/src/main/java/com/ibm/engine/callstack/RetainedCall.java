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
 * A recorded call that retains its live AST tree and scan context — today's behavior. While the
 * call's file is being analyzed, this form is used so same-file hook detections resolve and report
 * SonarQube issues through the live context.
 *
 * <p>If the call is detachable, {@link #detachedForm} carries a pre-built tree-free {@link
 * DetachedCall} (its arguments resolved at record time). When the call's file finishes analysis,
 * the {@link CallStackAgent} swaps this entry for {@link #detachedForm}, dropping the tree so the
 * file's AST becomes garbage-collectable while cross-file matching continues from the snapshot.
 */
public record RetainedCall<R, T>(
        @Nonnull T tree,
        @Nonnull IScanContext<R, T> publisher,
        @Nullable DetachedCall<R, T> detachedForm)
        implements CallContext<R, T> {}
