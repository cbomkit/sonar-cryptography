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
package com.ibm.engine.model.factory;

import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.Protocol;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public final class ProtocolFactory<T> implements IValueFactory<T> {

    @Nullable private final String constant;

    public ProtocolFactory() {
        this.constant = null;
    }

    public ProtocolFactory(@Nonnull String constant) {
        this.constant = constant;
    }

    /**
     * A constant protocol says the same thing for every input, so it can be stated from the
     * argument's presence alone. Without a constant the factory reads the resolved string and has
     * nothing to say about an argument it cannot resolve.
     */
    @Override
    public boolean isPresenceBased() {
        return constant != null;
    }

    @Override
    @Nonnull
    public Optional<IValue<T>> apply(ResolvedValue<Object, T> objectTResolvedValue) {
        if (constant != null) {
            return Optional.of(new Protocol<>(constant, objectTResolvedValue.tree()));
        }
        if (objectTResolvedValue.value() instanceof String str) {
            return Optional.of(new Protocol<>(str, objectTResolvedValue.tree()));
        }
        return Optional.empty();
    }
}
