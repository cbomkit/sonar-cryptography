/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2024 PQCA
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
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

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.mapper.model.INode;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.sslr.api.AstNode;
import org.sonar.cxx.sslr.api.Grammar;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

import static org.assertj.core.api.Assertions.assertThat;

public final class LibsodiumDetectionTest extends TestBase {

    @Test
    public void detectsLibsodiumHashAndAeadAlgorithms() {
        CxxVerifier.verify("libsodium/LibsodiumSample.c", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<SquidCheck<?>, AstNode, Symbol, SquidAstVisitorContext<? extends Grammar>> detectionStore,
            @Nonnull List<INode> nodes) {

        String algorithm = findFirstValueActionString(detectionStore);
        assertThat(algorithm).isNotNull();

        if (findingId == 0) {
            assertThat(algorithm).isEqualTo("BLAKE2B");
        } else if (findingId == 1) {
            assertThat(algorithm).isEqualTo("ChaCha20-Poly1305");
        } else {
            assertThat(algorithm).isIn("BLAKE2B", "ChaCha20-Poly1305");
        }
    }

    private static String findFirstValueActionString(DetectionStore<?, ?, ?, ?> store) {
        for (IValue value : store.getDetectionValues()) {
            if (value instanceof ValueAction<?> action) {
                return action.asString();
            }
        }

        for (DetectionStore<?, ?, ?, ?> child : store.getChildren()) {
            String result = findFirstValueActionString(child);
            if (result != null) {
                return result;
            }
        }

        return null;
    }
}
