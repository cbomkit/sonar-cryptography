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
package com.ibm.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ibm.mapper.model.ContextualEvidence;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.utils.DetectionLocation;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.sonar.api.batch.postjob.PostJobContext;
import org.sonar.api.config.Configuration;

class OutputFileJobTest {

    private Path tempDir;

    @BeforeEach
    void setUp() throws Exception {
        tempDir = Files.createTempDirectory("cbom-test-");
        new ScannerManager(null).reset();
    }

    @AfterEach
    void tearDown() {
        new ScannerManager(null).reset();
    }

    @Test
    void noCbomFileWrittenWhenAggregatorsAreEmpty() throws Exception {
        String cbomBaseName = tempDir.resolve("cbom").toAbsolutePath().toString();

        Configuration config = mock(Configuration.class);
        when(config.get(Constants.CBOM_OUTPUT_NAME)).thenReturn(Optional.of(cbomBaseName));

        PostJobContext context = mock(PostJobContext.class);
        when(context.config()).thenReturn(config);

        OutputFileJob job = new OutputFileJob();
        job.execute(context);

        File expectedCbomFile = new File(cbomBaseName + ".json");
        assertThat(expectedCbomFile)
                .as("CBOM file must not be written when no cryptographic assets were detected")
                .doesNotExist();
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(booleans = {false, true})
    void behaviorAnnotationsRequireExplicitOptIn(Boolean enabled) throws Exception {
        // Seed crypto and auth evidence to exercise both behavior sources in the saved CBOM.
        DetectionLocation location =
                new DetectionLocation("Test.java", 1, 0, List.of(), () -> "test");
        JavaAggregator.addNodes(
                List.of(new AES(location), new ContextualEvidence("JWT", location)));
        Path cbomFile = tempDir.resolve("cbom.json");
        Configuration config = mock(Configuration.class);
        when(config.get(Constants.CBOM_OUTPUT_NAME))
                .thenReturn(Optional.of(tempDir.resolve("cbom").toString()));
        when(config.getBoolean(Constants.BEHAVIORS_ENABLED))
                .thenReturn(Optional.ofNullable(enabled));
        PostJobContext context = mock(PostJobContext.class);
        when(context.config()).thenReturn(config);

        // Generate the actual output through the SonarQube post-job configuration path.
        new OutputFileJob().execute(context);

        // The inventory is always present; experimental annotations require an explicit true.
        ObjectMapper json = new ObjectMapper();
        JsonNode document = json.readTree(cbomFile.toFile());
        assertThat(document.path("components").findValuesAsText("name")).containsExactly("AES");
        JsonNode properties = document.at("/metadata/component/properties");
        if (Boolean.TRUE.equals(enabled)) {
            assertThat(properties.findValuesAsText("name")).containsExactly("cbomkit:behaviors");
            JsonNode behaviors = json.readTree(properties.get(0).path("value").asText());
            assertThat(behaviors.path("instances").findValuesAsText("behavior"))
                    .contains(
                            "security:cryptography:encryptsData",
                            "security:cryptography:authenticates",
                            "security:cryptography:validatesToken");
        } else {
            assertThat(document.at("/metadata/component").isMissingNode()).isTrue();
        }
    }
}
