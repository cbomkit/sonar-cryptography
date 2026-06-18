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
package com.ibm.mapper.model.algorithms.shake;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.ExtendableOutputFunction;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.IPrimitive;
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
 *   <li>https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 *   <li>customizable SHAKE
 * </ul>
 */
public final class CSHAKE extends Algorithm implements ExtendableOutputFunction {

    private static final String NAME = "cSHAKE"; // customizable SHAKE

    public CSHAKE(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, ExtendableOutputFunction.class, detectionLocation);
    }

    /** Returns a name of the form "cSHAKEXXX" where XXX is the parameter set identifer */
    @Override
    @Nonnull
    public String asString() {
        final StringBuilder builtName = new StringBuilder(this.name);
        final Optional<INode> parameterSetIdentifier =
                this.hasChildOfType(ParameterSetIdentifier.class);
        parameterSetIdentifier.ifPresent(node -> builtName.append(node.asString()));
        return builtName.toString();
    }

    public CSHAKE(int parameterSetIdentifier, @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(
                new ParameterSetIdentifier(
                        String.valueOf(parameterSetIdentifier), detectionLocation));
    }

    public CSHAKE(@Nonnull final Class<? extends IPrimitive> asKind, @Nonnull CSHAKE cSHAKE) {
        super(cSHAKE, asKind);
    }

    private CSHAKE(@Nonnull CSHAKE cSHAKE) {
        super(cSHAKE);
    }

    @Nonnull
    @Override
    protected CSHAKE shallowCopy() {
        return new CSHAKE(this);
    }
}
