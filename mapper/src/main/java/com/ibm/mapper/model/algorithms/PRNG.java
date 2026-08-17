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
package com.ibm.mapper.model.algorithms;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.PseudorandomNumberGenerator;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

/**
 *
 *
 * <h2>{@value #NAME}</h2>
 *
 * <p>Generic pseudorandom number generator, used when a specific PRNG/DRBG algorithm is requested
 * (e.g. via {@code SecureRandom.getInstance("DRBG")}) but no more specific model applies.
 */
public final class PRNG extends Algorithm implements PseudorandomNumberGenerator {
    private static final String NAME = "PRNG";

    public PRNG(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, PseudorandomNumberGenerator.class, detectionLocation);
    }
}
