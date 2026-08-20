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
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.ParameterSetIdentifier;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 *
 *
 * <h2>SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)</h2>
 *
 * <p>
 *
 * <h3>Specification</h3>
 *
 * <ul>
 *   <li>https://sphincs.org
 *   <li>https://csrc.nist.gov/pubs/fips/205/final
 *   <li>https://cyclonedx.org/schema/cryptography-defs.json (algorithmName: SLH-DSA)
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 *   <li>SPHINCS+
 * </ul>
 */
public class SPHINCSPlus extends Algorithm implements Signature {

    private static final String NAME = "SLH-DSA";

    @Override
    public @Nonnull String asString() {
        StringBuilder builtName = new StringBuilder(this.name);
        Optional<INode> parameterSetIdentifier = this.hasChildOfType(ParameterSetIdentifier.class);
        parameterSetIdentifier.ifPresent(node -> builtName.append("-").append(node.asString()));
        this.hasChildOfType(MessageDigest.class)
                .ifPresent(node -> builtName.append(node.asString()));
        return builtName.toString();
    }

    public SPHINCSPlus(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, Signature.class, detectionLocation);
    }

    public SPHINCSPlus(MessageDigest messageDigest) {
        this(messageDigest.getDetectionContext());
        this.put(messageDigest);
    }

    /**
     * Constructs an SLH-DSA node carrying a FIPS 205 parameter set identifier, e.g. {@code
     * "SHA2-128s"} or {@code "SHAKE-256f"}, so that {@link #asString()} yields {@code
     * "SLH-DSA-SHA2-128s"}. Used by the C# {@code SlhDsaAlgorithm}-parameterized detection rules
     * (see {@code DotNetSlhDsa}), which can recover the exact parameter set from the enum member
     * name at the call site.
     */
    public SPHINCSPlus(
            @Nonnull String parameterSetIdentifier, @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(new ParameterSetIdentifier(parameterSetIdentifier, detectionLocation));
    }
}
