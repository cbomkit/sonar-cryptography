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
package com.ibm.mapper.model.algorithms.blake;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.ExtendableOutputFunction;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

/**
 *
 *
 * <h2>{@value #NAME}</h2>
 *
 * <p>
 *
 * <h3>Specification</h3>
 *
 * <ul>
 *   <li>https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE2
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 * </ul>
 */
public final class BLAKE2X extends Algorithm implements ExtendableOutputFunction {

    private static final String NAME = "BLAKE2X";

    public BLAKE2X(@Nonnull MessageDigest blake2, @Nonnull DetectionLocation detectionLocation) {
        super(NAME, ExtendableOutputFunction.class, detectionLocation);
        this.put(blake2);
    }

    private BLAKE2X(@Nonnull BLAKE2X bLAKE2X) {
        super(bLAKE2X);
    }

    @Nonnull
    @Override
    protected BLAKE2X shallowCopy() {
        return new BLAKE2X(this);
    }
}
