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

public class EllipticCurve extends Property {
    @Nonnull private final String value;

    public EllipticCurve(@Nonnull String value, @Nonnull DetectionLocation detectionLocation) {
        super(EllipticCurve.class, detectionLocation);
        this.value = value;
    }

    /** A copy of the given curve without its children. */
    protected EllipticCurve(@Nonnull EllipticCurve ellipticCurve) {
        super(ellipticCurve);
        this.value = ellipticCurve.value;
    }

    @Nonnull
    public String getValue() {
        return value;
    }

    @Nonnull
    @Override
    public String asString() {
        return value;
    }

    /**
     * A curve class returns an instance of its own class, which the enrichers recognise the curve
     * by.
     */
    @Nonnull
    @Override
    protected EllipticCurve copy() {
        return new EllipticCurve(this);
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (!(object instanceof EllipticCurve that)) return false;
        if (!super.equals(object)) return false;
        return Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), value);
    }
}
