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
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.IPrimitive;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.ParameterSetIdentifier;
import com.ibm.mapper.model.algorithms.shake.CSHAKE;
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
 *   <li>https://www.cryptosys.net/manapi/api_kmac.html
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 * </ul>
 */
public final class KMAC extends Algorithm implements MessageDigest {

    private static final String NAME = "KMAC";

    /** Returns a name of the form "KMACXXX" where XXX is the parameter set identifer */
    @Override
    @Nonnull
    public String asString() {
        StringBuilder builtName = new StringBuilder(this.name);

        Optional<INode> parameterSetIdentifier = this.hasChildOfType(ParameterSetIdentifier.class);

        parameterSetIdentifier.ifPresent(node -> builtName.append(node.asString()));
        return builtName.toString();
    }

    public KMAC(@Nonnull DetectionLocation detectionLocation) {
        /* KMAC is a hash function mostly used as a MAC */
        super(NAME, Mac.class, detectionLocation);
        this.put(new CSHAKE(detectionLocation));
    }

    public KMAC(int parameterSetIdentifier, @Nonnull DetectionLocation detectionLocation) {
        /* KMAC is a hash function mostly used as a MAC */
        super(NAME, Mac.class, detectionLocation);
        this.put(
                new ParameterSetIdentifier(
                        String.valueOf(parameterSetIdentifier), detectionLocation));
        this.put(new CSHAKE(parameterSetIdentifier, detectionLocation));
        this.put(new DigestSize(2 * parameterSetIdentifier, detectionLocation));
    }

    public KMAC(@Nonnull final Class<? extends IPrimitive> asKind, @Nonnull KMAC kmac) {
        super(kmac, asKind);
    }

    private KMAC(@Nonnull KMAC kMAC) {
        super(kMAC);
    }

    @Nonnull
    @Override
    protected KMAC shallowCopy() {
        return new KMAC(this);
    }
}
