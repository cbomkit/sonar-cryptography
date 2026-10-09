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

public class Padding extends Property {
    @Nonnull private final String name;

    public Padding(@Nonnull String name, @Nonnull DetectionLocation detectionLocation) {
        super(Padding.class, detectionLocation);
        this.name = name;
    }

    protected Padding(
            @Nonnull String name,
            @Nonnull DetectionLocation detectionLocation,
            @Nonnull Class<? extends Padding> kind) {
        super(kind, detectionLocation);
        this.name = name;
    }

    /** A copy of the given padding without its children. */
    protected Padding(@Nonnull Padding padding) {
        super(padding);
        this.name = padding.name;
    }

    @Nonnull
    public String getName() {
        return name;
    }

    @Override
    public String toString() {
        return this.name;
    }

    @Nonnull
    @Override
    public String asString() {
        return name;
    }

    /**
     * A padding class returns an instance of its own class, which the output recognises the padding
     * by.
     */
    @Nonnull
    @Override
    protected Padding copy() {
        return new Padding(this);
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (!(object instanceof Padding padding)) return false;
        if (!super.equals(object)) return false;
        return Objects.equals(name, padding.name);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), name);
    }
}
