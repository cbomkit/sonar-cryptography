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

public class AlgorithmParameter<T> extends AbstractValue<T> {

    public enum Kind {
        ANY,
        N, // EC: order N
        A, // EC: A
        B, // EC: B
        P, // EC: P
        M, // EC: M
        ITERATIONS,
        DSA_L_AND_N
    }

    @Nonnull private final Kind kind;
    @Nonnull private final String parameter;
    @Nonnull private final T location;

    public AlgorithmParameter(
            @Nonnull final String parameter, @Nonnull final Kind kind, @Nonnull T location) {
        this.location = location;
        this.parameter = parameter;
        this.kind = kind;
    }

    @Override
    @Nonnull
    public T getLocation() {
        return location;
    }

    @Nonnull
    public Kind getKind() {
        return kind;
    }

    @Nonnull
    public String getParameter() {
        return parameter;
    }

    @Nonnull
    @Override
    public String asString() {
        return parameter;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AlgorithmParameter<?> that)) return false;

        return getKind() == that.getKind()
                && getParameter().equals(that.getParameter())
                && getLocation().equals(that.getLocation());
    }

    @Override
    public int hashCode() {
        int result = getKind().hashCode();
        result = 31 * result + getParameter().hashCode();
        result = 31 * result + getLocation().hashCode();
        return result;
    }
}
