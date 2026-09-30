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
package com.ibm.mapper.reorganizer.rules;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Key;
import com.ibm.mapper.model.PublicKey;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class KeyReorgenizerTest {

    private final DetectionLocation location = mock(DetectionLocation.class);

    @Test
    void theKeyIsReplacedInTheTreeOfItsRoot() {
        // an equal key of another tree comes before it among the roots
        final Key first = new Key(new RSA(location));
        first.put(new KeyGeneration(KeyGeneration.Specification.PRIVATE_KEY, location));
        final Key second = new Key(new RSA(location));
        second.put(new KeyGeneration(KeyGeneration.Specification.PUBLIC_KEY, location));
        assertThat(first).isEqualTo(second);
        final List<INode> roots = new ArrayList<>(List.of(first, second));

        final List<INode> result =
                KeyReorgenizer.SPECIFY_KEY_TYPE_BY_LOOKING_AT_KEY_GENERATION.applyReorganization(
                        second, null, roots);

        assertThat(result).hasSize(2);
        assertThat(result.get(0)).isSameAs(first);
        assertThat(result.get(1)).isInstanceOf(PublicKey.class);
    }
}
