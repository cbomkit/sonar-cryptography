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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.model.CipherSuite;
import com.ibm.mapper.model.ContextualEvidence;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Version;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.HMAC;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.collections.AssetCollection;
import com.ibm.mapper.model.collections.CipherSuiteCollection;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.model.mode.CBC;
import com.ibm.mapper.model.protocol.TLS;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.output.behavior.CryptoBehavior;
import com.ibm.output.cyclondx.BehaviorMetadataWriter;
import com.ibm.output.cyclondx.CBOMOutputFile;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import org.cyclonedx.generators.BomGeneratorFactory;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.Property;
import org.cyclonedx.parsers.JsonParser;
import org.junit.jupiter.api.Test;

class CryptoBehaviorMetadataTest {

    private final IBundle bundle = () -> "Test";
    private final DetectionLocation loc =
            new DetectionLocation("test.java", 1, 1, Collections.emptyList(), bundle);
    private final ObjectMapper json = new ObjectMapper();

    private Bom bomOf(List<INode> nodes) {
        final CBOMOutputFile outputFile = new CBOMOutputFile();
        nodes.forEach(node -> outputFile.add(List.of(node)));
        return outputFile.getBom();
    }

    private JsonNode behaviorDocument(Component component) throws Exception {
        final Property property =
                component.getProperties().stream()
                        .filter(p -> p.getName().equals("cbomkit:behaviors"))
                        .findFirst()
                        .orElseThrow();
        return json.readTree(property.getValue());
    }

    @Test
    void aggregatesBehaviorsOfWholeScanOntoMetadataComponent() throws Exception {
        // Collect crypto operations from several assets in the same application.
        final AES aes = new AES(loc);
        aes.put(new Encrypt(loc));
        final Bom bom = bomOf(List.of(aes, new SHA2(256, loc), new HMAC(loc)));

        // Store sorted behavior instances in one JSON-valued property.
        final Component metaComponent = bom.getMetadata().getComponent();
        assertThat(metaComponent).isNotNull();
        assertThat(metaComponent.getType()).isEqualTo(Component.Type.APPLICATION);
        assertThat(metaComponent.getBomRef()).isNotBlank();
        assertThat(metaComponent.getProperties()).hasSize(1);
        final JsonNode document = behaviorDocument(metaComponent);
        final JsonNode instances = document.get("instances");
        assertThat(instances.isArray()).isTrue();
        assertThat(instances.findValuesAsText("behavior"))
                .containsExactly(
                        "security:cryptography:encryptsData",
                        "security:cryptography:ensuresConfidentiality",
                        "security:cryptography:ensuresIntegrity",
                        "security:cryptography:hashesData");

        // Every instance references the application and has its own ID.
        assertThat(instances.findValuesAsText("bom-ref")).doesNotHaveDuplicates();
        for (JsonNode instance : instances) {
            assertThat(instance.path("bom-ref").asText())
                    .isNotBlank()
                    .isNotEqualTo(metaComponent.getBomRef());
            assertThat(instance.get("actors").size()).isEqualTo(1);
            assertThat(instance.get("actors").get(0).asText()).isEqualTo(metaComponent.getBomRef());
        }

        // Static findings do not supply runtime details or ordered flows.
        assertThat(document.size()).isEqualTo(1);
        for (JsonNode instance : instances) {
            assertThat(instance.size()).isEqualTo(3);
            assertThat(instance.has("acknowledgment")).isFalse();
            assertThat(instance.has("trigger")).isFalse();
            assertThat(instance.has("targets")).isFalse();
        }
    }

    @Test
    void authInterfaceUnlocksAuthenticatesAndValidatesToken() throws Exception {
        final AES aes = new AES(loc);
        aes.put(new Encrypt(loc));
        final Bom bom = bomOf(List.of(aes, new ContextualEvidence("JWT", loc)));

        final JsonNode document = behaviorDocument(bom.getMetadata().getComponent());
        assertThat(document.get("instances").findValuesAsText("behavior"))
                .contains("security:cryptography:authenticates")
                .contains("security:cryptography:validatesToken")
                .contains("security:cryptography:encryptsData");
    }

    @Test
    void noMetadataComponentWhenNoBehaviorsDetected() {
        // A functionality without an algorithm contributes no behaviors.
        final Bom bom = bomOf(List.of(new Encrypt(loc)));
        assertThat(bom.getMetadata().getComponent()).isNull();
    }

    @Test
    void protocolCipherSuiteConstituentsContributeBehaviors() throws Exception {
        // Include an algorithm nested inside a protocol cipher suite.
        final TLS tls = new TLS(new Version("1.3", loc));
        final CipherSuite cipherSuite = new CipherSuite("TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", loc);
        final AES aes = new AES(256, new CBC(loc), loc);
        final AssetCollection assetCollection = new AssetCollection(List.of(aes));
        cipherSuite.put(assetCollection);
        tls.put(new CipherSuiteCollection(List.of(cipherSuite)));

        final Bom bom = bomOf(List.of(tls));

        // The nested cipher contributes its fallback behaviors.
        final Component metaComponent = bom.getMetadata().getComponent();
        assertThat(metaComponent).isNotNull();
        final JsonNode document = behaviorDocument(metaComponent);
        assertThat(document.get("instances").findValuesAsText("behavior"))
                .contains(
                        "security:cryptography:decryptsData",
                        "security:cryptography:encryptsData",
                        "security:cryptography:ensuresConfidentiality");
    }

    @Test
    void authOnlyScanHasBehaviorInstancesWithoutCryptoComponents() throws Exception {
        final Bom bom = bomOf(List.of(new ContextualEvidence("JWT", loc)));
        assertThat(bom.getComponents()).isEmpty();
        assertThat(
                        behaviorDocument(bom.getMetadata().getComponent())
                                .get("instances")
                                .findValuesAsText("behavior"))
                .containsExactly(
                        "security:cryptography:authenticates",
                        "security:cryptography:validatesToken");
    }

    @Test
    void preservesExistingApplicationAndProperties() throws Exception {
        // Start with application details and an immutable list of unrelated properties.
        final Metadata metadata = new Metadata();
        final Component application = new Component();
        application.setType(Component.Type.APPLICATION);
        application.setName("checkout-api");
        application.setVersion("1.2.3");
        application.setBomRef("urn:example:checkout");
        final Property owner = new Property();
        owner.setName("example:owner");
        owner.setValue("payments");
        application.setProperties(List.of(owner));
        metadata.setComponent(application);

        // Add behaviors without replacing the component or its existing values.
        BehaviorMetadataWriter.attachIfPresent(metadata, Set.of(CryptoBehavior.ENCRYPTS_DATA));

        // The actor is a reference to the application, not its display name.
        assertThat(metadata.getComponent()).isSameAs(application);
        assertThat(application.getName()).isEqualTo("checkout-api");
        assertThat(application.getType()).isEqualTo(Component.Type.APPLICATION);
        assertThat(application.getVersion()).isEqualTo("1.2.3");
        assertThat(application.getBomRef()).isEqualTo("urn:example:checkout");
        assertThat(application.getProperties()).hasSize(2).contains(owner);
        assertThat(
                        behaviorDocument(application)
                                .get("instances")
                                .get(0)
                                .get("actors")
                                .get(0)
                                .asText())
                .isEqualTo("urn:example:checkout");
    }

    @Test
    void assignsAReferenceToAnExistingApplication() throws Exception {
        final Metadata metadata = new Metadata();
        final Component application = new Component();
        application.setName("checkout-api");
        metadata.setComponent(application);

        // An existing component without a reference can still act in the behavior model.
        BehaviorMetadataWriter.attachIfPresent(metadata, Set.of(CryptoBehavior.WRAPS_KEY));

        assertThat(application.getBomRef()).isNotBlank();
        assertThat(application.getName()).isEqualTo("checkout-api");
        assertThat(
                        behaviorDocument(application)
                                .get("instances")
                                .get(0)
                                .get("actors")
                                .get(0)
                                .asText())
                .isEqualTo(application.getBomRef());
    }

    @Test
    void repeatedWritesReplaceThePropertyAndKeepInstanceIdsStable() throws Exception {
        // Save the first instance's ID before the set of behaviors grows.
        final Metadata metadata = new Metadata();
        BehaviorMetadataWriter.attachIfPresent(metadata, Set.of(CryptoBehavior.ENCRYPTS_DATA));
        final Component application = metadata.getComponent();
        final String originalId =
                behaviorDocument(application).get("instances").get(0).get("bom-ref").asText();

        // Rewriting the property adds the new behavior without changing the existing ID.
        BehaviorMetadataWriter.attachIfPresent(
                metadata, Set.of(CryptoBehavior.WRAPS_KEY, CryptoBehavior.ENCRYPTS_DATA));

        assertThat(application.getProperties()).hasSize(1);
        final JsonNode instances = behaviorDocument(application).get("instances");
        assertThat(instances.findValuesAsText("behavior"))
                .containsExactly(
                        "security:cryptography:encryptsData", "security:cryptography:wrapsKey");
        assertThat(instances.get(0).get("bom-ref").asText()).isEqualTo(originalId);
        assertThat(instances.get(1).get("bom-ref").asText()).isNotEqualTo(originalId);
    }

    @Test
    void differentActorsGetDifferentInstanceIds() throws Exception {
        // The same behavior can belong to different applications.
        final Metadata first = new Metadata();
        final Metadata second = new Metadata();
        final Component otherApplication = new Component();
        otherApplication.setBomRef("urn:example:other-application");
        second.setComponent(otherApplication);

        BehaviorMetadataWriter.attachIfPresent(first, Set.of(CryptoBehavior.WRAPS_KEY));
        BehaviorMetadataWriter.attachIfPresent(second, Set.of(CryptoBehavior.WRAPS_KEY));

        // Instance IDs include the actor identity, so the two records stay distinct.
        final String firstId =
                behaviorDocument(first.getComponent())
                        .get("instances")
                        .get(0)
                        .get("bom-ref")
                        .asText();
        final String secondId =
                behaviorDocument(second.getComponent())
                        .get("instances")
                        .get(0)
                        .get("bom-ref")
                        .asText();
        assertThat(firstId).isNotEqualTo(secondId);
    }

    @Test
    void emptyBehaviorsLeaveExistingMetadataUntouched() {
        final Metadata metadata = new Metadata();
        final Component application = new Component();
        application.setName("checkout-api");
        metadata.setComponent(application);

        BehaviorMetadataWriter.attachIfPresent(metadata, Set.of());

        assertThat(metadata.getComponent()).isSameAs(application);
        assertThat(application.getName()).isEqualTo("checkout-api");
        assertThat(application.getBomRef()).isNull();
        assertThat(application.getProperties()).isNull();
    }

    @Test
    void serializesAsAValidCycloneDx16Property() throws Exception {
        // Generate the actual 1.6 document, including the JSON-encoded property value.
        final Bom bom = bomOf(List.of(new ContextualEvidence("JWT", loc)));
        final String serialized =
                BomGeneratorFactory.createJson(org.cyclonedx.Version.VERSION_16, bom)
                        .toJsonString();
        final JsonNode document = json.readTree(serialized);

        // The behavior container is carried as a string inside a standard 1.6 property.
        assertThat(new JsonParser().validate(serialized, org.cyclonedx.Version.VERSION_16))
                .isEmpty();
        assertThat(document.get("specVersion").asText()).isEqualTo("1.6");
        assertThat(document.has("behaviors")).isFalse();
        final JsonNode property = document.at("/metadata/component/properties/0");
        assertThat(property.get("name").asText()).isEqualTo("cbomkit:behaviors");
        assertThat(property.get("value").isTextual()).isTrue();
        assertThat(json.readTree(property.get("value").asText()))
                .isEqualTo(behaviorDocument(bom.getMetadata().getComponent()));
    }
}
