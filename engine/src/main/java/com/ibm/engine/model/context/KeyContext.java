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

import java.util.Map;
import javax.annotation.Nonnull;

@SuppressWarnings("java:S115")
public class KeyContext extends DetectionContext {
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

    /**
     * use a property map instead
     *
     * @deprecated
     */
    @Deprecated(since = "1.3.0")
    public KeyContext(@Nonnull Kind kind) {
        super(Map.of("kind", kind.name()));
    }

    public KeyContext() {
        super(Map.of("kind", Kind.NONE.name()));
    }

    public KeyContext(@Nonnull Map<String, String> properties) {
        super(properties);
    }

    /**
     * use a property map instead
     *
     * @deprecated
     */
    @Deprecated(since = "1.3.0")
    @Nonnull
    public Kind kind() {
        try {
            return Kind.valueOf(get("kind").orElse(Kind.NONE.name()));
        } catch (IllegalArgumentException e) {
            return Kind.NONE;
        }
    }

    @Nonnull
    @Override
    public Class<? extends DetectionContext> type() {
        return KeyContext.class;
    }
}
