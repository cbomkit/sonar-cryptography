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
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.Unknown;
import com.ibm.mapper.model.algorithms.Dilithium;
import com.ibm.mapper.model.algorithms.Falcon;
import com.ibm.mapper.model.algorithms.GMSS;
import com.ibm.mapper.model.algorithms.GeMSS;
import com.ibm.mapper.model.algorithms.HSS;
import com.ibm.mapper.model.algorithms.LMS;
import com.ibm.mapper.model.algorithms.Picnic;
import com.ibm.mapper.model.algorithms.QTESLA;
import com.ibm.mapper.model.algorithms.Rainbow;
import com.ibm.mapper.model.algorithms.SPHINCS;
import com.ibm.mapper.model.algorithms.SPHINCSPlus;
import com.ibm.mapper.model.algorithms.XMSS;
import com.ibm.mapper.model.algorithms.XMSSMT;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class BcMessageSignerMapper implements IMapper {

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
            @Nonnull String signerString, @Nonnull DetectionLocation detectionLocation) {
        return switch (signerString) {
            case "DilithiumSigner" -> Optional.of(new Dilithium(detectionLocation));
            case "FalconSigner" -> Optional.of(new Falcon(detectionLocation));
            case "GeMSSSigner" -> Optional.of(new GeMSS(detectionLocation));
            case "GMSSSigner" -> Optional.of(new GMSS(detectionLocation));
            case "HSSSigner" -> Optional.of(new HSS(detectionLocation));
            case "LMSSigner" -> Optional.of(new LMS(detectionLocation));
            case "PicnicSigner" -> Optional.of(new Picnic(detectionLocation));
            case "QTESLASigner" -> Optional.of(new QTESLA(detectionLocation));
            case "RainbowSigner" -> Optional.of(new Rainbow(detectionLocation));
            case "SPHINCSPlusSigner" -> Optional.of(new SPHINCSPlus(detectionLocation));
            case "SPHINCS256Signer" -> Optional.of(new SPHINCS(256, detectionLocation));
            /* StateAwareMessageSigner subinterface */
            case "XMSSMTSigner" -> Optional.of(new XMSSMT(detectionLocation));
            case "XMSSSigner" -> Optional.of(new XMSS(detectionLocation));
            case "GMSSStateAwareSigner" -> Optional.of(new GMSS(detectionLocation));
            default -> {
                final Algorithm algorithm =
                        new Algorithm(signerString, Signature.class, detectionLocation);
                algorithm.put(new Unknown(detectionLocation));
                yield Optional.of(algorithm);
            }
        };
    }
}
