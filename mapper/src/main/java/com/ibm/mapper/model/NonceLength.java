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
package com.ibm.mapper.model;

import com.ibm.mapper.utils.DetectionLocation;
import java.util.Objects;
import javax.annotation.Nonnull;

public final class NonceLength extends Property {
    @Nonnull private final Integer value; // in bit

    public NonceLength(@Nonnull Integer value, @Nonnull DetectionLocation detectionLocation) {
        super(NonceLength.class, detectionLocation);
        this.value = value;
    }

    private NonceLength(@Nonnull NonceLength nonceLength) {
        super(nonceLength);
        this.value = nonceLength.value;
    }

    @Nonnull
    public Integer getValue() {
        return value;
    }

    @Nonnull
    @Override
    public String asString() {
        return value.toString();
    }

    @Nonnull
    @Override
    protected NonceLength copy() {
        return new NonceLength(this);
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (!(object instanceof NonceLength nonceLength)) return false;
        if (!super.equals(object)) return false;
        return Objects.equals(value, nonceLength.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), value);
    }
}
