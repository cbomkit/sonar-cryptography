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

public final class BlockSize extends Property {
    @Nonnull private final Integer value; // bit

    public BlockSize(@Nonnull Integer value, @Nonnull DetectionLocation detectionLocation) {
        super(BlockSize.class, detectionLocation);
        this.value = value;
    }

    public BlockSize(
            @Nonnull Integer value,
            @Nonnull DetectionLocation detectionLocation,
            @Nonnull NodeOrigin origin) {
        super(BlockSize.class, detectionLocation, origin);
        this.value = value;
    }

    private BlockSize(@Nonnull BlockSize blockSize) {
        super(blockSize.type, blockSize.detectionLocation, blockSize.children, blockSize.origin);
        this.value = blockSize.value;
    }

    /**
     * Creates a BlockSize with DEFAULT origin, for use in algorithm constructors.
     *
     * @param value the block size in bits
     * @param detectionLocation the detection location
     * @return a new BlockSize marked as DEFAULT
     */
    @Nonnull
    public static BlockSize ofDefault(
            @Nonnull Integer value, @Nonnull DetectionLocation detectionLocation) {
        return new BlockSize(value, detectionLocation, NodeOrigin.DEFAULT);
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
        BlockSize copy = new BlockSize(this);
        for (INode child : this.children.values()) {
            copy.children.put(child.getKind(), child.deepCopy());
        }
        return copy;
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (!(object instanceof BlockSize blockSize)) return false;
        if (!super.equals(object)) return false;
        return Objects.equals(value, blockSize.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), value);
    }
}
