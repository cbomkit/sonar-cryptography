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
package com.ibm.output.cyclonedx;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.model.Version;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.protocol.TLS;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.output.cyclondx.DetectionProperties;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Property;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.junit.jupiter.api.Test;

class DetectionPropertiesTest extends TestBase {

    private static final String RULE_BINARY =
            "csharp:FoDicom:DicomClientFactory,IDicomClientFactory|Create";
    private static final String RULE_CONFIG = "config:dotnet:SslProtocols";

    private DetectionLocation binary() {
        return new DetectionLocation(
                "src/Service.cs",
                42,
                0,
                List.of(RULE_BINARY),
                bundle,
                Map.of(
                        DetectionProperties.CONFIDENCE, "high",
                        DetectionProperties.POLARITY, "permitted",
                        DetectionProperties.ORIGIN, "third-party",
                        DetectionProperties.STORE_KIND, "library-default",
                        DetectionProperties.RULE_ID, RULE_BINARY,
                        DetectionProperties.SOURCE, "binary"));
    }

    private DetectionLocation config() {
        return new DetectionLocation(
                "app.config",
                7,
                0,
                List.of(RULE_CONFIG),
                bundle,
                Map.of(
                        DetectionProperties.CONFIDENCE, "medium",
                        DetectionProperties.POLARITY, "required",
                        DetectionProperties.RULE_ID, RULE_CONFIG,
                        DetectionProperties.SOURCE, "config"));
    }

    private static Map<String, String> properties(Component component) {
        assertThat(component.getProperties()).isNotNull();
        return component.getProperties().stream()
                .collect(Collectors.toMap(Property::getName, Property::getValue));
    }

    @Test
    void dedupedComponentAggregatesValuesAndKeepsPerOccurrenceFacts() {
        this.assertsNodes(
                () ->
                        List.of(
                                new TLS(new Version("1.2", binary())),
                                new TLS(new Version("1.2", config()))),
                bom -> {
                    assertThat(bom.getComponents()).hasSize(1);
                    final Component tls = bom.getComponents().get(0);
                    assertThat(tls.getName()).isEqualTo("TLSv1.2");

                    final Map<String, String> properties = properties(tls);
                    assertThat(properties)
                            .containsEntry(DetectionProperties.CONFIDENCE, "high,medium")
                            .containsEntry(DetectionProperties.POLARITY, "permitted,required")
                            .containsEntry(DetectionProperties.SOURCE, "binary,config")
                            // only one occurrence had them: no invented second value
                            .containsEntry(DetectionProperties.ORIGIN, "third-party")
                            .containsEntry(DetectionProperties.STORE_KIND, "library-default")
                            // absence: unbounded per-occurrence facts are never aggregated on the
                            // component; the occurrences carry them
                            .doesNotContainKeys(
                                    DetectionProperties.SUBJECT,
                                    DetectionProperties.LOCATOR,
                                    DetectionProperties.RULE_ID);
                    // property list is in key order
                    assertThat(tls.getProperties().stream().map(Property::getName)).isSorted();

                    final List<Occurrence> occurrences = tls.getEvidence().getOccurrences();
                    assertThat(occurrences).hasSize(2);
                    assertThat(occurrences)
                            .anySatisfy(
                                    o -> {
                                        assertThat(o.getLocation()).isEqualTo("src/Service.cs");
                                        assertThat(o.getAdditionalContext())
                                                .isEqualTo(
                                                        "confidence=high; polarity=permitted;"
                                                                + " origin=third-party;"
                                                                + " storeKind=library-default; rule="
                                                                + RULE_BINARY);
                                    })
                            .anySatisfy(
                                    o -> {
                                        assertThat(o.getLocation()).isEqualTo("app.config");
                                        assertThat(o.getAdditionalContext())
                                                .isEqualTo(
                                                        "confidence=medium; polarity=required; rule="
                                                                + RULE_CONFIG);
                                    });
                });
    }

    @Test
    void sameFactsTwiceGiveOneValue() {
        this.assertsNodes(
                () ->
                        List.of(
                                new RSA(binary()),
                                new RSA(binary().withProperties(binary().properties()))),
                bom -> {
                    assertThat(bom.getComponents()).hasSize(1);
                    final Component rsa = bom.getComponents().get(0);
                    assertThat(properties(rsa))
                            .containsEntry(DetectionProperties.CONFIDENCE, "high");
                    assertThat(rsa.getEvidence().getOccurrences()).hasSize(1);
                });
    }

    @Test
    void nodeWithoutPropertiesYieldsNoProperties() {
        this.assertsNodes(
                () ->
                        List.of(
                                new RSA(detectionLocation),
                                new TLS(new Version("1.3", detectionLocation))),
                bom -> {
                    assertThat(bom.getComponents()).hasSize(2);
                    for (Component component : bom.getComponents()) {
                        assertThat(component.getProperties()).isNull();
                        asserts(component.getEvidence());
                    }
                });
    }

    @Test
    void sourceOccurrenceMergedWithDetectionKeepsItsPlainContext() {
        final DetectionLocation source =
                new DetectionLocation("src/Main.java", 1, 1, List.of("getInstance"), bundle);
        this.assertsNodes(
                () -> List.of(new RSA(source), new RSA(binary())),
                bom -> {
                    final Component rsa = bom.getComponents().get(0);
                    // only the detection-backed occurrence contributes values
                    assertThat(properties(rsa))
                            .containsEntry(DetectionProperties.CONFIDENCE, "high");
                    assertThat(rsa.getEvidence().getOccurrences())
                            .extracting(Occurrence::getAdditionalContext)
                            .contains("getInstance")
                            .anyMatch(c -> c.startsWith("confidence=high;"));
                });
    }

    @Test
    void withPropertiesCopiesAndEmptyMeansNone() {
        final DetectionLocation copy = detectionLocation.withProperties(Map.of("k", "v"));
        assertThat(copy.properties()).containsExactly(Map.entry("k", "v"));
        assertThat(detectionLocation.properties()).isEmpty();
        assertThat(copy.withProperties(Map.of())).isEqualTo(detectionLocation);
        assertThat(DetectionProperties.occurrenceContext(Map.of("k", "v"))).isEmpty();
    }
}
