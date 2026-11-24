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
package com.ibm.plugin.translation.translator.contexts;

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.DESede;
import com.ibm.mapper.model.algorithms.PBES2;
import com.ibm.mapper.model.algorithms.PKCS12PBE;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.mode.CBC;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Maps a {@code PbeEncryptionAlgorithm} or {@code Pkcs12ExportPbeParameters} member name to the
 * scheme it selects.
 *
 * <p>The AES members give PBES2 with AES in CBC mode. {@code TripleDes3KeyPkcs12} gives the PKCS#12
 * scheme with three-key Triple DES (168 bits). The {@code Pkcs12ExportPbeParameters} members also
 * name the hash. {@code Unknown}, {@code Default} and any other name give nothing.
 */
public final class DotNetPbeEncryptionNames {

    private DotNetPbeEncryptionNames() {
        // utility
    }

    /** Returns the scheme, with its cipher attached, that a member name selects. */
    @Nonnull
    public static Optional<INode> parse(
            @Nonnull String encryptionAlgorithmName, @Nonnull DetectionLocation detectionLocation) {
        return switch (encryptionAlgorithmName.trim()) {
            case "Aes128Cbc" -> Optional.of(pbes2WithAes(128, detectionLocation));
            case "Aes192Cbc" -> Optional.of(pbes2WithAes(192, detectionLocation));
            case "Aes256Cbc" -> Optional.of(pbes2WithAes(256, detectionLocation));
            case "TripleDes3KeyPkcs12" -> Optional.of(pkcs12WithTripleDes(detectionLocation));
            // Pkcs12ExportPbeParameters names the hash too. Default is left out: it depends on the
            // .NET version.
            case "Pbes2Aes256Sha256" -> {
                final PBES2 scheme = pbes2WithAes(256, detectionLocation);
                scheme.put(new SHA2(256, detectionLocation));
                yield Optional.of(scheme);
            }
            case "Pkcs12TripleDesSha1" -> {
                final PKCS12PBE scheme = pkcs12WithTripleDes(detectionLocation);
                scheme.put(new SHA(detectionLocation));
                yield Optional.of(scheme);
            }
            default -> Optional.empty();
        };
    }

    @Nonnull
    private static PBES2 pbes2WithAes(int keyBits, @Nonnull DetectionLocation detectionLocation) {
        final PBES2 scheme = new PBES2(detectionLocation);
        scheme.put(new AES(keyBits, new CBC(detectionLocation), detectionLocation));
        return scheme;
    }

    @Nonnull
    private static PKCS12PBE pkcs12WithTripleDes(@Nonnull DetectionLocation detectionLocation) {
        final PKCS12PBE scheme = new PKCS12PBE(detectionLocation);
        scheme.put(new DESede(168, new CBC(detectionLocation), detectionLocation));
        return scheme;
    }
}
