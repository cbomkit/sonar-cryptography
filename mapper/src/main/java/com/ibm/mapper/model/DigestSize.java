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

public final class DigestSize extends Property {
    @Nonnull private final Integer value; // bit

    public DigestSize(@Nonnull Integer value, @Nonnull DetectionLocation detectionLocation) {
        super(DigestSize.class, detectionLocation);
        this.value = value;
    }

    private DigestSize(
            @Nonnull Integer value,
            @Nonnull DetectionLocation detectionLocation,
            @Nonnull NodeOrigin origin) {
        super(DigestSize.class, detectionLocation, origin);
        this.value = value;
    }

    private DigestSize(@Nonnull DigestSize digestSize) {
        super(
                digestSize.type,
                digestSize.detectionLocation,
                digestSize.children,
                digestSize.origin);
        this.value = digestSize.value;
    }

    /**
     * Creates a DigestSize with DEFAULT origin, for use in algorithm constructors where the size is
     * a known constant rather than something directly detected in source code.
     */
    @Nonnull
    public static DigestSize ofDefault(
            @Nonnull Integer value, @Nonnull DetectionLocation detectionLocation) {
        return new DigestSize(value, detectionLocation, NodeOrigin.DEFAULT);
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
    public INode deepCopy() {
        DigestSize copy = new DigestSize(this);
        for (INode child : this.children.values()) {
            copy.children.put(child.getKind(), child.deepCopy());
        }
        return copy;
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (!(object instanceof DigestSize that)) return false;
        if (!super.equals(object)) return false;
        return Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), value);
    }
}
