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
package com.ibm.engine.model;

import javax.annotation.Nonnull;

public class KeyAction<T> extends AbstractValue<T> implements IAction<T> {

    public enum Action {
        PRIVATE_KEY_GENERATION,
        PUBLIC_KEY_GENERATION,
        SECRET_KEY_GENERATION,
        GENERATION,
        ENCAPSULATION,
        DECAPSULATION,
        KDF
    }

    @Nonnull private final Action action;
    @Nonnull private final T location;

    public KeyAction(@Nonnull Action action, @Nonnull T location) {
        this.location = location;
        this.action = action;
    }

    @Override
    @Nonnull
    public T getLocation() {
        return location;
    }

    @Nonnull
    public Action getAction() {
        return action;
    }

    @Nonnull
    @Override
    public String asString() {
        return action.toString();
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof KeyAction<?> keyAction)) return false;

        return action == keyAction.action && location.equals(keyAction.location);
    }

    @Override
    public int hashCode() {
        int result = action.hashCode();
        result = 31 * result + location.hashCode();
        return result;
    }
}
