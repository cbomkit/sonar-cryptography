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
import com.ibm.mapper.model.ParameterSetIdentifier;
import com.ibm.mapper.model.Signature;
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
 *   <li>https://eprint.iacr.org/2014/795.pdf
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 * </ul>
 */
public class SPHINCS extends Algorithm implements Signature {

    private static final String NAME = "SPHINCS";

    @Override
    public @Nonnull String asString() {
        return this.hasChildOfType(ParameterSetIdentifier.class)
                .map(node -> this.name + "-" + node.asString())
                .orElse(this.name);
    }

    public SPHINCS(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, Signature.class, detectionLocation);
    }

    public SPHINCS(int parameterSetIdentifier, @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(
                new ParameterSetIdentifier(
                        String.valueOf(parameterSetIdentifier), detectionLocation));
    }

    private SPHINCS(@Nonnull SPHINCS sPHINCS) {
        super(sPHINCS);
    }

    @Nonnull
    @Override
    protected SPHINCS shallowCopy() {
        return new SPHINCS(this);
    }
}
