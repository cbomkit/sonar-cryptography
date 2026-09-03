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

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

class KeyTest {

    /**
     * A small test-only subclass to exercise the protected recast constructor {@link Key#Key(Key,
     * DetectionLocation, Class)}.
     */
    private static final class TestKey extends Key {
        TestKey(@Nonnull Key key, @Nonnull DetectionLocation detectionLocation) {
            super(key, detectionLocation, TestKey.class);
        }
    }

    @Test
    void recastConstructor_shouldCopyChildrenMap() {
        DetectionLocation detectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        // Create an original key with a child via its IAlgorithm constructor
        Algorithm algorithm = new Algorithm("AES", BlockCipher.class, detectionLocation);
        Key original = new Key(algorithm);

        // Verify the original has children
        assertThat(original.getChildren()).isNotEmpty();

        // Recast the key using the protected constructor
        TestKey recast = new TestKey(original, detectionLocation);

        // The children maps must not be the same instance
        assertThat(recast.getChildren()).isNotSameAs(original.getChildren());

        // The children maps must have equal content
        assertThat(recast.getChildren()).isEqualTo(original.getChildren());

        // Mutating the recast's children must not affect the original
        recast.getChildren().clear();
        assertThat(original.getChildren()).isNotEmpty();
        assertThat(original.hasChildOfType(BlockCipher.class)).isPresent();
    }
}
