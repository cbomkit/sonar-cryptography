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

import java.util.Objects;
import javax.annotation.Nonnull;

public class ProtocolContext implements IDetectionContext, ISupportKind<ProtocolContext.Kind> {

    public enum Kind {
        TLS,
        NONE,
    }

    @Nonnull private final ProtocolContext.Kind kind;

    public ProtocolContext(@Nonnull ProtocolContext.Kind kind) {
        this.kind = kind;
    }

    public ProtocolContext() {
        this.kind = ProtocolContext.Kind.NONE;
    }

    @Nonnull
    @Override
    public Class<? extends IDetectionContext> type() {
        return ProtocolContext.class;
    }

    @Nonnull
    @Override
    public Kind kind() {
        return this.kind;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (other == null || getClass() != other.getClass()) {
            return false;
        }
        return kind == ((ProtocolContext) other).kind;
    }

    @Override
    public int hashCode() {
        return Objects.hash(getClass(), kind);
    }
}
