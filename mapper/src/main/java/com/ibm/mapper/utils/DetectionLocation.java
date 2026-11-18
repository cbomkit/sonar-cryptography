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
package com.ibm.mapper.utils;

import com.ibm.engine.rule.IBundle;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import javax.annotation.Nonnull;

/**
 * Where a finding was made.
 *
 * <p>{@code properties} are free-form string facts about the finding that the CBOM writer carries
 * into the output (see {@code com.ibm.output.cyclondx.DetectionProperties} for the keys in use).
 * Language modules leave them empty; the detections translator fills them from a detections
 * document. The map is copied into an immutable, key-sorted map.
 */
public record DetectionLocation(
        @Nonnull String filePath,
        @Nonnull Integer lineNumber,
        @Nonnull Integer offSet,
        @Nonnull List<String> keywords,
        @Nonnull IBundle bundle,
        @Nonnull Map<String, String> properties) {

    public DetectionLocation {
        properties =
                properties == null || properties.isEmpty()
                        ? Map.of()
                        : Collections.unmodifiableMap(new TreeMap<>(properties));
    }

    /** A location without properties, as every source scan creates it. */
    public DetectionLocation(
            @Nonnull String filePath,
            @Nonnull Integer lineNumber,
            @Nonnull Integer offSet,
            @Nonnull List<String> keywords,
            @Nonnull IBundle bundle) {
        this(filePath, lineNumber, offSet, keywords, bundle, Map.of());
    }

    /** A copy of this location with the given properties instead of the current ones. */
    @Nonnull
    public DetectionLocation withProperties(@Nonnull Map<String, String> newProperties) {
        return new DetectionLocation(filePath, lineNumber, offSet, keywords, bundle, newProperties);
    }
}
