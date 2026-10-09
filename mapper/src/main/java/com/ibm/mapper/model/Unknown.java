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
import javax.annotation.Nonnull;

public final class Unknown extends Property implements IPrimitive {

    public Unknown(@Nonnull DetectionLocation detectionLocation) {
        super(Unknown.class, detectionLocation);
    }

    private Unknown(@Nonnull Unknown unknown) {
        super(unknown);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Unknown unknown)) return false;

        return detectionLocation.equals(unknown.detectionLocation);
    }

    @Override
    public int hashCode() {
        return detectionLocation.hashCode();
    }

    @Nonnull
    @Override
    public String asString() {
        return "Unknown";
    }

    @Override
    @Nonnull
    public String toString() {
        return this.asString();
    }

    @Nonnull
    @Override
    protected Unknown copy() {
        return new Unknown(this);
    }

    @Nonnull
    @Override
    public String getName() {
        return this.asString();
    }
}
