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
package com.ibm.engine.model.context;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import javax.annotation.Nonnull;

@SuppressWarnings("java:S115")
public class KeyContext extends DetectionContext
        implements IDetectionContext, ISupportKind<KeyContext.Kind> {
    public enum Kind {
        /* TODO: they are still used in JCA and Python, but should be removed */
        EC,
        DES,
        DESede,
        DH,
        DSA,
        PBE,
        KDF,
        KEM,
        NONE,
        UNKNOWN;
    }

    @Nonnull private final Kind kind;

    /**
     * use a property map instead
     *
     * @deprecated
     */
    @Deprecated(since = "1.3.0")
    public KeyContext(@Nonnull Kind kind) {
        super(new HashMap<>());
        this.kind = kind;
    }

    public KeyContext() {
        super(new HashMap<>());
        this.kind = Kind.NONE;
    }

    public KeyContext(@Nonnull Map<String, String> properties) {
        super(properties);
        this.kind = Kind.NONE;
    }

    /**
     * use a property map instead
     *
     * @deprecated
     */
    @Deprecated(since = "1.3.0")
    @Nonnull
    public Kind kind() {
        return kind;
    }

    @Nonnull
    @Override
    public Class<? extends IDetectionContext> type() {
        return KeyContext.class;
    }

    @Override
    public boolean equals(Object other) {
        return super.equals(other) && kind == ((KeyContext) other).kind;
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), kind);
    }
}
