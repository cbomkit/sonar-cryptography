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
package com.ibm.output.cyclondx;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.ibm.output.behavior.CryptoBehavior;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import javax.annotation.Nonnull;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.Property;

/** Writes security behavior instances to CBOM metadata. */
public final class BehaviorMetadataWriter {

    public static final String BEHAVIOR_PROPERTY_NAME = "cbomkit:behaviors";

    // Use a fixed name because no scanned-software name is supplied to getBom().
    private static final String METADATA_COMPONENT_NAME = "scanned-application";
    private static final String APPLICATION_BOM_REF = "scanned-application";

    private BehaviorMetadataWriter() {}

    /** Attaches the behavior property to {@code metadata.component}; no-op when empty. */
    public static void attachIfPresent(
            @Nonnull Metadata metadata, @Nonnull Set<CryptoBehavior> behaviors) {
        if (behaviors.isEmpty()) {
            return;
        }

        // Reuse the application component and give it a reference for the behavior actors.
        Component softwareComponent = metadata.getComponent();
        if (softwareComponent == null) {
            softwareComponent = new Component();
            softwareComponent.setType(Component.Type.APPLICATION);
            softwareComponent.setName(METADATA_COMPONENT_NAME);
            metadata.setComponent(softwareComponent);
        }
        if (softwareComponent.getBomRef() == null || softwareComponent.getBomRef().isBlank()) {
            softwareComponent.setBomRef(APPLICATION_BOM_REF);
        }

        // Replace our property while keeping any other application properties.
        final List<Property> properties = new ArrayList<>();
        if (softwareComponent.getProperties() != null) {
            properties.addAll(softwareComponent.getProperties());
        }
        properties.removeIf(property -> BEHAVIOR_PROPERTY_NAME.equals(property.getName()));
        final Property behaviorProperty = new Property();
        behaviorProperty.setName(BEHAVIOR_PROPERTY_NAME);
        behaviorProperty.setValue(behaviorJson(softwareComponent.getBomRef(), behaviors));
        properties.add(behaviorProperty);
        softwareComponent.setProperties(properties);
    }

    @Nonnull
    private static String behaviorJson(
            @Nonnull String actorRef, @Nonnull Set<CryptoBehavior> behaviors) {
        // Write one instance per behavior, in a stable order.
        final ObjectNode document = JsonNodeFactory.instance.objectNode();
        final ArrayNode instances = document.putArray("instances");
        behaviors.stream()
                .map(CryptoBehavior::fullId)
                .sorted()
                .forEach(
                        behavior -> {
                            // Keep the instance ID stable for the same actor and behavior.
                            final UUID instanceId =
                                    UUID.nameUUIDFromBytes(
                                            (actorRef + "\n" + behavior)
                                                    .getBytes(StandardCharsets.UTF_8));
                            final ObjectNode instance = instances.addObject();
                            instance.put("bom-ref", "urn:cbomkit:behavior:" + instanceId);
                            instance.put("behavior", behavior);
                            instance.putArray("actors").add(actorRef);
                        });

        // CycloneDX 1.6 property values must be strings.
        return document.toString();
    }
}
