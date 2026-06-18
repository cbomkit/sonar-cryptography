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
import com.ibm.mapper.model.ClassicalBitSecurityLevel;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.IPrimitive;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.StreamCipher;
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
 *   <li>http://www.is.cas.cn/ztzl2016/zouchongzhi/201801/W020180416526664982687.pdf
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 * </ul>
 */
public final class ZUC extends Algorithm implements StreamCipher, Mac {

    private static final String NAME = "ZUC";

    public ZUC(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, StreamCipher.class, detectionLocation);
    }

    /** Returns a name of the form "ZUC-XXX" where XXX is the bit security level */
    @Override
    @Nonnull
    public String asString() {
        StringBuilder builtName = new StringBuilder(this.name);

        Optional<INode> securityLevel = this.hasChildOfType(ClassicalBitSecurityLevel.class);

        if (securityLevel.isPresent()) {
            builtName.append("-").append(securityLevel.get().asString());
        }

        return builtName.toString();
    }

    public ZUC(int securityLevel, @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(new ClassicalBitSecurityLevel(securityLevel, detectionLocation));
    }

    public ZUC(@Nonnull final Class<? extends IPrimitive> asKind, @Nonnull ZUC zuc) {
        super(zuc, asKind);
    }

    private ZUC(@Nonnull ZUC zUC) {
        super(zUC);
    }

    @Nonnull
    @Override
    protected ZUC shallowCopy() {
        return new ZUC(this);
    }
}
