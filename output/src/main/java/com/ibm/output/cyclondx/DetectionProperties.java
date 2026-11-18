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

import java.util.List;
import java.util.Map;
import java.util.StringJoiner;
import javax.annotation.Nonnull;

/**
 * Keys of the per-detection facts that a {@link com.ibm.mapper.utils.DetectionLocation} may carry
 * in its {@code properties} and that {@link CBOMOutputFile} writes into the CBOM.
 *
 * <p>External scanners that produce findings outside this plugin (for example of compiled binaries
 * or shipped configuration) fill them; source scans leave them empty, and a location without
 * properties produces no component {@code properties} and no extra occurrence context.
 *
 * <p>Components are deduplicated by name across occurrences, so a component property holds the
 * <b>set</b> of distinct values seen for that key, sorted and joined by {@value #VALUE_SEPARATOR}
 * (e.g. {@code cbom:confidence = high,medium}). What each single occurrence claimed is written to
 * that occurrence's {@code additionalContext} (see {@link #occurrenceContext}).
 */
public final class DetectionProperties {

    public static final String CONFIDENCE = "cbom:confidence";
    public static final String POLARITY = "cbom:polarity";
    public static final String ORIGIN = "cbom:origin";
    public static final String STORE_KIND = "cbom:storeKind";
    public static final String RULE_ID = "cbom:ruleId";
    public static final String SOURCE = "cbom:source";
    public static final String SUBJECT = "cbom:subject";
    public static final String LOCATOR = "cbom:locator";

    /**
     * The system-wide crypto policy ({@code DEFAULT}, {@code LEGACY}, {@code FUTURE}, ...) a config
     * detection read; carried by the unversioned TLS component the policy governs.
     */
    public static final String CRYPTO_POLICY = "cbom:cryptoPolicy";

    /**
     * The further paths of byte-identical copies of the subject file, joined by {@value
     * #VALUE_SEPARATOR} (config scanner, {@code alsoAt}).
     */
    public static final String ALSO_AT = "cbom:alsoAt";

    /**
     * The facts aggregated per component: closed, small value sets, so the union across all of a
     * component's occurrences stays readable ({@code high,medium}). Locator, subject and rule id
     * are per-occurrence facts -- unbounded, and on a deduplicated component a list of them would
     * only repeat the occurrences -- so they go into each occurrence's context instead.
     */
    public static final List<String> COMPONENT_FACTS =
            List.of(CONFIDENCE, POLARITY, ORIGIN, STORE_KIND, SOURCE, CRYPTO_POLICY);

    /** Separator of the distinct values aggregated into one component property. */
    public static final String VALUE_SEPARATOR = ",";

    /** The facts repeated per occurrence, with their short names in {@code additionalContext}. */
    private static final List<Map.Entry<String, String>> OCCURRENCE_FACTS =
            List.of(
                    Map.entry(CONFIDENCE, "confidence"),
                    Map.entry(POLARITY, "polarity"),
                    Map.entry(ORIGIN, "origin"),
                    Map.entry(STORE_KIND, "storeKind"),
                    Map.entry(RULE_ID, "rule"),
                    Map.entry(LOCATOR, "locator"),
                    Map.entry(SUBJECT, "subject"),
                    Map.entry(CRYPTO_POLICY, "cryptoPolicy"),
                    Map.entry(ALSO_AT, "alsoAt"));

    private DetectionProperties() {
        // constants
    }

    /**
     * The per-occurrence context: {@code confidence=high; polarity=permitted; origin=third-party;
     * storeKind=library-default; rule=csharp:...; locator=...; subject=...; cryptoPolicy=...;
     * alsoAt=...}, in that order, absent facts left out. Empty when none of these facts is present.
     */
    @Nonnull
    public static String occurrenceContext(@Nonnull Map<String, String> properties) {
        final StringJoiner joiner = new StringJoiner("; ");
        for (Map.Entry<String, String> fact : OCCURRENCE_FACTS) {
            final String value = properties.get(fact.getKey());
            if (value != null) {
                joiner.add(fact.getValue() + "=" + value);
            }
        }
        return joiner.toString();
    }
}
