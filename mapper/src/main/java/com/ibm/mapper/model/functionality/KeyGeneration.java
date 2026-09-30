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
package com.ibm.mapper.model.functionality;

import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public final class KeyGeneration extends Functionality {

    public enum Specification {
        PRIVATE_KEY,
        PUBLIC_KEY,
        SECRET_KEY,
    }

    @Nullable private final Specification specification;

    public KeyGeneration(@Nonnull DetectionLocation detectionLocation) {
        super(KeyGeneration.class, detectionLocation);
        this.specification = null;
    }

    public KeyGeneration(
            @Nonnull Specification specification, @Nonnull DetectionLocation detectionLocation) {
        super(KeyGeneration.class, detectionLocation);
        this.specification = specification;
    }

    private KeyGeneration(@Nonnull Functionality functionality) {
        super(functionality);
        if (functionality instanceof KeyGeneration keyGeneration) {
            this.specification = keyGeneration.specification;
        } else {
            this.specification = null;
        }
    }

    @Nonnull
    public Optional<Specification> getSpecification() {
        return Optional.ofNullable(specification);
    }

    @Nonnull
    @Override
    protected KeyGeneration copy() {
        return new KeyGeneration(this);
    }
}
