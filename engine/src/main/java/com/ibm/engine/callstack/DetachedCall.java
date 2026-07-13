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

import com.ibm.engine.detection.IType;
import com.ibm.engine.language.IScanContext;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * A recorded call stored tree-free: the match keys and pre-resolved argument snapshots are captured
 * at record time while the file is live, so the file's AST becomes garbage-collectable afterwards.
 *
 * <p>Matching uses {@link #invokedObjectType()} / {@link #methodName()} / {@link #parameterTypes()}
 * via {@code MethodMatcher.matchKeys}; hook replay reads {@link #arguments()}.
 */
public record DetachedCall<R, T>(
        @Nonnull IType invokedObjectType,
        @Nonnull String methodName,
        @Nonnull List<IType> parameterTypes,
        @Nonnull List<ArgSnapshot> arguments,
        @Nonnull DetachedScanContext<R, T> detachedPublisher)
        implements CallContext<R, T> {

    @Nullable @Override
    public T tree() {
        return null;
    }

    @Nonnull
    @Override
    public IScanContext<R, T> publisher() {
        return detachedPublisher;
    }
}
