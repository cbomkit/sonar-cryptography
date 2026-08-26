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
import com.ibm.engine.model.Mode;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class ModeFactory<T> implements IValueFactory<T> {

    @Nullable private final String constant;

    public ModeFactory() {
        this.constant = null;
    }

    /**
     * Creates a factory that always emits {@code Mode(constant)} regardless of the resolved
     * parameter value. Useful when the mode is encoded in the method name (e.g. {@code EncryptCbc})
     * rather than in a parameter.
     */
    public ModeFactory(@Nonnull String constant) {
        this.constant = constant;
    }

    @Override
    public Optional<IValue<T>> apply(@Nonnull ResolvedValue<Object, T> objectTResolvedValue) {
        if (constant != null) {
            return Optional.of(new Mode<>(constant, objectTResolvedValue.tree()));
        }
        if (objectTResolvedValue.value() instanceof String s) {
            return Optional.of(new Mode<>(s, objectTResolvedValue.tree()));
        }
        return Optional.empty();
    }
}
