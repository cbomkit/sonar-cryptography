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
import com.ibm.mapper.model.DigestSize;
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
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 *   *
 * </ul>
 */
public final class SHAKE extends Algorithm implements ExtendableOutputFunction {
    private static final String NAME = "SHAKE";

    public SHAKE(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, ExtendableOutputFunction.class, detectionLocation);
    }

    /** Returns a name of the form "SHAKEXXX" where XXX is the parameter set identifer */
    @Override
    @Nonnull
    public String asString() {
        final StringBuilder builtName = new StringBuilder(this.name);
        // check for parameter set identifier
        final Optional<INode> parameterSetIdentifier =
                this.hasChildOfType(ParameterSetIdentifier.class);
        parameterSetIdentifier.ifPresent(node -> builtName.append(node.asString()));
        // check for digest size
        final Optional<INode> digestSize = this.hasChildOfType(DigestSize.class);
        digestSize.ifPresent(node -> builtName.append(node.asString()));
        return builtName.toString();
    }

    public SHAKE(int parameterSetIdentifier, @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(
                new ParameterSetIdentifier(
                        String.valueOf(parameterSetIdentifier), detectionLocation));
    }

    public SHAKE(@Nonnull final Class<? extends IPrimitive> asKind, @Nonnull SHAKE shake) {
        super(shake, asKind);
    }

    private SHAKE(@Nonnull SHAKE sHAKE) {
        super(sHAKE);
    }

    @Nonnull
    @Override
    protected SHAKE shallowCopy() {
        return new SHAKE(this);
    }
}
