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

public class IterationCount<T> extends AbstractValue<T> {
    @Nonnull private final Integer value;
    @Nonnull private final T location;

    public IterationCount(@Nonnull Integer value, @Nonnull T location) {
        this.location = location;
        this.value = value;
    }

    @Override
    @Nonnull
    public T getLocation() {
        return location;
    }

    @Nonnull
    public Integer getValue() {
        return value;
    }

    @Override
    public String toString() {
        return value.toString();
    }

    @Nonnull
    @Override
    public String asString() {
        return toString();
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof IterationCount<?> that)) return false;

        return value.equals(that.value) && location.equals(that.location);
    }

    @Override
    public int hashCode() {
        int result = value.hashCode();
        result = 31 * result + location.hashCode();
        return result;
    }
}
