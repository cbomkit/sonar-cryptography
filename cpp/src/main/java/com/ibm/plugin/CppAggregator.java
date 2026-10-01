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

import com.ibm.mapper.model.INode;
import com.ibm.output.IAggregator;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Static accumulator for C/C++ cryptographic detection results.
 *
 * <p>This keeps C/C++ aligned with other language modules while C/C++ detection rules are being
 * implemented incrementally.
 */
public final class CppAggregator implements IAggregator {

    private static List<INode> detectedNodes = new ArrayList<>();

    private CppAggregator() {
        // nothing
    }

    @Nonnull
    public static List<INode> getDetectedNodes() {
        return Collections.unmodifiableList(detectedNodes);
    }

    public static void addNodes(@Nonnull List<INode> newNodes) {
        detectedNodes.addAll(newNodes);
        IAggregator.log(newNodes);
    }

    public static void reset() {
        detectedNodes = new ArrayList<>();
    }
}
