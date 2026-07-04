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

import com.ibm.engine.model.context.AuthContext;
import com.ibm.engine.model.context.IDetectionContext;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;
import javax.annotation.Nonnull;

/**
 * Scan-wide accumulator of non-crypto contextual signals (design §4.3). Holds the set of detected
 * authentication-interface kinds. Written from {@link
 * com.ibm.plugin.rules.detection.JavaBaseDetectionRule} when it routes an {@link AuthContext}
 * finding; read by {@code ScannerManager} and passed into the output factory. Static and reset per
 * scan, mirroring {@link JavaAggregator}.
 */
public final class BehaviorEvidenceStore {

    private static Set<AuthContext.Kind> signals = EnumSet.noneOf(AuthContext.Kind.class);

    private BehaviorEvidenceStore() {
        // nothing
    }

    public static boolean recordFrom(@Nonnull IDetectionContext context) {
        if (context instanceof AuthContext authContext
                && authContext.kind() != AuthContext.Kind.NONE) {
            signals.add(authContext.kind());
            return true;
        }
        return false;
    }

    @Nonnull
    public static Set<AuthContext.Kind> getSignals() {
        return Collections.unmodifiableSet(signals);
    }

    public static void reset() {
        signals = EnumSet.noneOf(AuthContext.Kind.class);
    }
}
