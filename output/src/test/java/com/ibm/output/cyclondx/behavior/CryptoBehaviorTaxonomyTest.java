/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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
package com.ibm.output.cyclondx.behavior;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

class CryptoBehaviorTaxonomyTest {

    private Set<String> taxonomyIdentifiers() throws Exception {
        final Set<String> ids = new HashSet<>();
        try (InputStream in =
                getClass().getClassLoader().getResourceAsStream("crypto-behavior-taxonomy.json")) {
            assertThat(in).as("crypto-behavior-taxonomy.json must be on the classpath").isNotNull();
            final JsonNode root = new ObjectMapper().readTree(in);
            assertThat(root.isArray()).isTrue();
            root.forEach(node -> ids.add(node.get("identifier").asText()));
        }
        return ids;
    }

    @Test
    void everyEmittedBehaviorExistsInTheTaxonomySnapshot() throws Exception {
        final Set<String> ids = taxonomyIdentifiers();
        for (CryptoBehavior behavior : CryptoBehavior.values()) {
            assertThat(ids)
                    .as("taxonomy snapshot is missing %s", behavior.fullId())
                    .contains(behavior.fullId());
        }
    }

    @Test
    void fullIdIsNamespaced() {
        assertThat(CryptoBehavior.ENCRYPTS_DATA.fullId())
                .isEqualTo("security:cryptography:encryptsData");
    }
}
