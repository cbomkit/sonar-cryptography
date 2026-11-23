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
package com.ibm.plugin.translation.model;

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Property;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Objects;
import javax.annotation.Nonnull;

/**
 * Temporary marker for the {@code truncate} option of PyCryptodome's {@code SHA512.new(...)}.
 *
 * <p>It is attached to the SHA-512 node during translation and consumed by {@link
 * com.ibm.plugin.translation.reorganizer.PythonDigestReorganizer#WRAP_SHA512_TRUNCATED}, which
 * replaces the node by the SHA-512/224 or SHA-512/256 variant. It is deliberately not a {@link
 * com.ibm.mapper.model.DigestSize}, so it never competes with the intrinsic digest size of the
 * SHA-512 node, and it must never reach the output.
 */
public final class Sha512Truncation extends Property {
    @Nonnull private final Integer value; // bit

    /** Truncation sizes accepted by {@code SHA512.new(truncate=...)}: SHA-512/224 and /256. */
    public static boolean isSupported(int bits) {
        return bits == 224 || bits == 256;
    }

    public Sha512Truncation(@Nonnull Integer value, @Nonnull DetectionLocation detectionLocation) {
        super(Sha512Truncation.class, detectionLocation);
        this.value = value;
    }

    private Sha512Truncation(@Nonnull Sha512Truncation other) {
        super(other.type, other.detectionLocation, other.children, other.origin);
        this.value = other.value;
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
        final Sha512Truncation copy = new Sha512Truncation(this);
        for (INode child : this.children.values()) {
            copy.children.put(child.getKind(), child.deepCopy());
        }
        return copy;
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (!(object instanceof Sha512Truncation that)) return false;
        if (!super.equals(object)) return false;
        return Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), value);
    }
}
