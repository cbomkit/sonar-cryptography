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
package com.ibm.plugin.rules.detection;

import com.ibm.engine.rule.IDetectionRule;
import com.ibm.plugin.rules.detection.libsodium.LibsodiumDetectionRules;
import com.ibm.plugin.rules.detection.openssl.OpenSSLDetectionRules;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/**
 * Registry of C++ cryptography detection rules.
 *
 * <p>This class aggregates all detection rules for C++ cryptographic libraries. Detection rules are
 * organized by library (e.g., OpenSSL, BoringSSL, libsodium).
 *
 * <p>To add new detection rules:
 *
 * <ol>
 *   <li>Create a new package under {@code rules.detection} for the library
 *   <li>Create detection rule classes following the pattern in Java module
 *   <li>Create a {@code *DetectionRules} class that returns all rules for the library
 *   <li>Add the rules to the stream in {@link #rules()}
 * </ol>
 */
public final class CxxDetectionRules {
    private CxxDetectionRules() {
        // private
    }

    /**
     * Returns all C++ cryptography detection rules.
     *
     * @return List of all detection rules
     */
    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return Stream.of(
                        OpenSSLDetectionRules.rules().stream(),
                        LibsodiumDetectionRules.rules().stream())
                .flatMap(i -> i)
                .toList();
    }
}
