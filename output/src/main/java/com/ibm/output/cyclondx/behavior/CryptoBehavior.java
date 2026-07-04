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

import javax.annotation.Nonnull;

/**
 * Experimental crypto behaviors from the CycloneDX 2.0-dev threat-modeling taxonomy ({@code
 * security:cryptography:*}). Only the subset this plugin can emit is represented here; the full
 * draft list is mirrored in {@code crypto-behavior-taxonomy.json}.
 */
public enum CryptoBehavior {
    ENCRYPTS_DATA("encryptsData"),
    DECRYPTS_DATA("decryptsData"),
    SIGNS_DATA("signsData"),
    VERIFIES_SIGNATURE("verifiesSignature"),
    HASHES_DATA("hashesData"),
    HASHES_PASSWORD("hashesPassword"),
    GENERATES_KEY("generatesKey"),
    GENERATES_RANDOM_VALUE("generatesRandomValue"),
    EXCHANGES_KEY("exchangesKey"),
    WRAPS_KEY("wrapsKey"),
    AUTHENTICATES("authenticates"),
    VALIDATES_TOKEN("validatesToken"),
    USES_IDENTITY("usesIdentity"),
    ENSURES_CONFIDENTIALITY("ensuresConfidentiality"),
    ENSURES_INTEGRITY("ensuresIntegrity"),
    ENSURES_NON_REPUDIATION("ensuresNonRepudiation");

    private static final String NAMESPACE = "security:cryptography:";

    @Nonnull private final String leafName;

    CryptoBehavior(@Nonnull String leafName) {
        this.leafName = leafName;
    }

    @Nonnull
    public String fullId() {
        return NAMESPACE + this.leafName;
    }
}
