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
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;

/**
 * Lazily builds and caches a rule list so that shared detection-rule subtrees are constructed once
 * and referenced everywhere, instead of being re-materialized at every embed site. The cached value
 * is an immutable snapshot ({@link List#copyOf}); the delegate runs at most once.
 */
public final class Memoize {

    private Memoize() {
        // utility
    }

    @Nonnull
    public static Supplier<List<IDetectionRule<AstNode>>> of(
            @Nonnull Supplier<List<IDetectionRule<AstNode>>> delegate) {
        return new Supplier<>() {
            private volatile List<IDetectionRule<AstNode>> value;

            @Override
            public List<IDetectionRule<AstNode>> get() {
                List<IDetectionRule<AstNode>> snapshot = value;
                if (snapshot == null) {
                    synchronized (this) {
                        snapshot = value;
                        if (snapshot == null) {
                            snapshot = List.copyOf(delegate.get());
                            value = snapshot;
                        }
                    }
                }
                return snapshot;
            }
        };
    }
}
