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

import com.ibm.output.behavior.CryptoBehavior;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import javax.annotation.Nonnull;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.Property;

/**
 * Experimental: serializes the scan-wide crypto behavior summary as one namespaced property on a
 * synthetic {@code metadata.component}. The only CycloneDX-specific part of the behavior subsystem
 * — inference lives in {@code com.ibm.output.behavior}.
 */
public final class BehaviorMetadataWriter {

    public static final String BEHAVIOR_PROPERTY_NAME = "cbomkit:crypto:behavior";

    // Intentional simplification of spec §4.4: use a fixed name because no scanned-software
    // name is plumbed into getBom(); the ideal value would be the scanned project name.
    private static final String METADATA_COMPONENT_NAME = "application";

    private BehaviorMetadataWriter() {}

    /** Attaches the behavior property to {@code metadata.component}; no-op when empty. */
    public static void attachIfPresent(
            @Nonnull Metadata metadata, @Nonnull Set<CryptoBehavior> behaviors) {
        if (behaviors.isEmpty()) {
            return;
        }
        final Component softwareComponent = new Component();
        softwareComponent.setType(Component.Type.APPLICATION);
        softwareComponent.setName(METADATA_COMPONENT_NAME);
        final String value =
                behaviors.stream()
                        .map(CryptoBehavior::fullId)
                        .sorted()
                        .collect(Collectors.joining(","));
        final Property behaviorProperty = new Property();
        behaviorProperty.setName(BEHAVIOR_PROPERTY_NAME);
        behaviorProperty.setValue(value);
        softwareComponent.setProperties(List.of(behaviorProperty));
        metadata.setComponent(softwareComponent);
    }
}
