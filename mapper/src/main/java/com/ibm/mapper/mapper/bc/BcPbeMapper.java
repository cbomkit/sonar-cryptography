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
package com.ibm.mapper.mapper.bc;

import com.ibm.mapper.mapper.IMapper;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.PasswordBasedEncryption;
import com.ibm.mapper.model.Unknown;
import com.ibm.mapper.model.algorithms.MD5;
import com.ibm.mapper.model.algorithms.PBES1;
import com.ibm.mapper.model.algorithms.PBES2;
import com.ibm.mapper.model.algorithms.PKCS12PBE;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class BcPbeMapper implements IMapper {

    @Override
    @Nonnull
    public Optional<? extends INode> parse(
            @Nullable String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }
        return map(str, detectionLocation);
    }

    @Nonnull
    private Optional<? extends INode> map(
            @Nonnull String pbeString, @Nonnull DetectionLocation detectionLocation) {
        return switch (pbeString) {
            case "OpenSSLPBEParametersGenerator" -> Optional.of(new PBES1(detectionLocation));
            case "OpenSSLPBEParametersGenerator[MD5]" -> {
                PBES1 pbe = new PBES1(detectionLocation);
                pbe.put(new MD5(detectionLocation));
                yield Optional.of(pbe);
            }
            case "PKCS12ParametersGenerator" -> Optional.of(new PKCS12PBE(detectionLocation));
            case "PKCS5S1ParametersGenerator" -> Optional.of(new PBES1(detectionLocation));
            case "PKCS5S2ParametersGenerator" -> Optional.of(new PBES2(detectionLocation));
            default -> {
                final Algorithm algorithm =
                        new Algorithm(pbeString, PasswordBasedEncryption.class, detectionLocation);
                algorithm.put(new Unknown(detectionLocation));
                yield Optional.of(algorithm);
            }
        };
    }
}
