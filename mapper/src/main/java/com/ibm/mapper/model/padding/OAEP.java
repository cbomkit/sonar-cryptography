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
package com.ibm.mapper.model.padding;

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MaskGenerationFunction;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;

/** OptimalAsymmetricEncryptionPadding */
public final class OAEP extends Padding {
    private static final String NAME = "OAEP";

    public OAEP(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, detectionLocation);
    }

    public OAEP(
            @Nonnull MessageDigest messageDigest, @Nonnull DetectionLocation detectionLocation) {
        super(NAME, detectionLocation);
        this.put(messageDigest);
    }

    public OAEP(
            @Nonnull MessageDigest messageDigest,
            @Nonnull MaskGenerationFunction maskGenerationFunction) {
        super(NAME, messageDigest.getDetectionContext());
        this.put(messageDigest);
        this.put(maskGenerationFunction);
    }

    @Nonnull
    public Optional<MessageDigest> getDigest() {
        INode node = this.getChildren().get(MessageDigest.class);
        if (node == null) {
            return Optional.empty();
        }
        return Optional.of((MessageDigest) node);
    }

    @Nonnull
    public Optional<MaskGenerationFunction> getMGF() {
        INode node = this.getChildren().get(MaskGenerationFunction.class);
        if (node == null) {
            return Optional.empty();
        }
        return Optional.of((MaskGenerationFunction) node);
    }

    private OAEP(@Nonnull OAEP oaep) {
        super(oaep);
    }

    @Nonnull
    @Override
    protected OAEP copy() {
        return new OAEP(this);
    }
}
