/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2025 PQCA
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
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.ParameterSetIdentifier;
import com.ibm.mapper.model.Signature;
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
 *   <li>Module-Lattice-Based Digital Signature
 *   <li>Standardized version of Dilithium
 * </ul>
 */
public class MLDSA extends Algorithm implements Signature {
    private static final String NAME = "ML-DSA";

    /** Returns a name of the form "ML-DSA-XXX" where XXX is the parameter set identifer */
    @Override
    @Nonnull
    public String asString() {
        StringBuilder builtName =
                new StringBuilder(
                        this.hasChildOfType(MessageDigest.class)
                                .map(node -> node.asString() + "with" + this.name)
                                .orElse(this.name));
        Optional<INode> parameterSetIdentifier = this.hasChildOfType(ParameterSetIdentifier.class);
        parameterSetIdentifier.ifPresent(node -> builtName.append("-").append(node.asString()));
        return builtName.toString();
    }

    public MLDSA(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, Signature.class, detectionLocation);
    }

    public MLDSA(@Nonnull MessageDigest preHash) {
        this(preHash.getDetectionContext());
        this.put(preHash);
    }

    public MLDSA(int parameterSetIdentifier, @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(
                new ParameterSetIdentifier(
                        String.valueOf(parameterSetIdentifier), detectionLocation));
    }

    public MLDSA(int parameterSetIdentifier, @Nonnull MessageDigest preHash) {
        this(preHash.getDetectionContext());
        this.put(preHash);
        this.put(
                new ParameterSetIdentifier(
                        String.valueOf(parameterSetIdentifier), preHash.getDetectionContext()));
    }

    private MLDSA(@Nonnull MLDSA mLDSA) {
        super(mLDSA);
    }

    @Nonnull
    @Override
    protected MLDSA shallowCopy() {
        return new MLDSA(this);
    }
}
