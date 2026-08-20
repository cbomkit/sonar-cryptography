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
package com.ibm.engine.model.context;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import javax.annotation.Nonnull;

public abstract class DetectionContext implements IDetectionContext {
    @Nonnull private final Map<String, String> properties;

    protected DetectionContext(@Nonnull Map<String, String> properties) {
        this.properties = Collections.unmodifiableMap(new HashMap<>(properties));
    }

    public boolean contains(@Nonnull String key) {
        return properties.containsKey(key);
    }

    @Nonnull
    public Optional<String> get(@Nonnull String key) {
        return Optional.ofNullable(properties.get(key));
    }

    @Override
    public String toString() {
        return properties.keySet().stream()
                .map(key -> key + "=" + properties.get(key))
                .collect(Collectors.joining(", ", "{", "}"));
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (other == null || getClass() != other.getClass()) {
            return false;
        }
        return properties.equals(((DetectionContext) other).properties);
    }

    @Override
    public int hashCode() {
        return Objects.hash(getClass(), properties);
    }
}
