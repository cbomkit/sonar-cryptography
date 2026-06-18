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
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyEncapsulationMechanism;
import com.ibm.mapper.model.ParameterSetIdentifier;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
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
 *   <li>https://csrc.nist.gov/pubs/fips/203/final
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 *   <li>Module-Lattice-Based Key-Encapsulation
 *   <li>Standardized version of Kyber
 * </ul>
 */
public final class MLKEM extends Algorithm implements KeyEncapsulationMechanism {

    private static final String NAME = "ML-KEM";

    /** Returns a name of the form "ML-KEM-XXX" where XXX is the parameter set identifer */
    @Override
    @Nonnull
    public String asString() {
        StringBuilder builtName = new StringBuilder(this.name);

        Optional<INode> parameterSetIdentifier = this.hasChildOfType(ParameterSetIdentifier.class);

        parameterSetIdentifier.ifPresent(node -> builtName.append("-").append(node.asString()));
        return builtName.toString();
    }

    public MLKEM(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, KeyEncapsulationMechanism.class, detectionLocation);
    }

    public MLKEM(int parameterSetIdentifier, @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(
                new ParameterSetIdentifier(
                        String.valueOf(parameterSetIdentifier), detectionLocation));
    }

    private MLKEM(@Nonnull MLKEM mLKEM) {
        super(mLKEM);
    }

    @Nonnull
    @Override
    protected MLKEM shallowCopy() {
        return new MLKEM(this);
    }
}
