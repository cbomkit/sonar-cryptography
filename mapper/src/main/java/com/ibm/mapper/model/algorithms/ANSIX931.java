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
import com.ibm.mapper.model.IPrimitive;
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
 *   <li>https://www.cryptsoft.com/pkcs11doc/v220/group__SEC__12__1__13__ANSI__X9__31__RSA.html
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 * </ul>
 */
public final class ANSIX931 extends Algorithm implements Signature {

    private static final String NAME = "ANSI X9.31";

    public ANSIX931(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, Signature.class, detectionLocation);
    }

    private ANSIX931(@Nonnull ANSIX931 algorithm) {
        super(algorithm);
    }

    @Nonnull
    @Override
    protected ANSIX931 copy() {
        return new ANSIX931(this);
    }

    public ANSIX931(@Nonnull final Class<? extends IPrimitive> asKind, @Nonnull ANSIX931 ansix931) {
        super(ansix931, asKind);
    }

    @Nonnull
    @Override
    public ANSIX931 asKind(@Nonnull Class<? extends IPrimitive> kind) {
        return new ANSIX931(kind, this);
    }
}
