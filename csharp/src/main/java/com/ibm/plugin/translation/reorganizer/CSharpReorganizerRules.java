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
package com.ibm.plugin.translation.reorganizer;

import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.Key;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.PublicKey;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.SecretKey;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.model.functionality.Verify;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.rules.CipherSuiteReorganizer;
import com.ibm.mapper.reorganizer.rules.KeyDerivationReorganizer;
import com.ibm.mapper.reorganizer.rules.PaddingReorganizer;
import com.ibm.mapper.reorganizer.rules.SignatureReorganizer;
import java.util.List;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/** Reorganizer rules for the C# translation pipeline. Delegates to existing shared rules. */
public final class CSharpReorganizerRules {

    private CSharpReorganizerRules() {
        // nothing
    }

    @Nonnull
    public static List<IReorganizerRule> rules() {
        return Stream.concat(
                        Stream.of(
                                SignatureReorganizer.MERGE_SIGNATURE_PARENT_AND_CHILD,
                                KeyDerivationReorganizer.moveModeFromParentToNode(
                                        BlockCipher.class),
                                KeyDerivationReorganizer.moveModeFromParentToNode(
                                        MessageDigest.class),
                                CipherSuiteReorganizer.REPLACE_TLS_WITH_VERSIONED_CHILD,
                                PaddingReorganizer.MOVE_OAEP_UNDER_ALGORITHM),
                        paddingLifts())
                .toList();
    }

    /**
     * .NET names a padding on the operation rather than on the creation, so it arrives under the
     * functionality node. Lift it onto the algorithm for every shape that can carry one, otherwise
     * the CBOM reports the algorithm without its padding.
     */
    @Nonnull
    private static Stream<IReorganizerRule> paddingLifts() {
        return Stream.of(
                        PublicKeyEncryption.class,
                        Key.class,
                        PrivateKey.class,
                        PublicKey.class,
                        SecretKey.class)
                .flatMap(
                        holder ->
                                Stream.of(Encrypt.class, Decrypt.class, Sign.class, Verify.class)
                                        .map(
                                                functionality ->
                                                        PaddingReorganizer.movePaddingToAlgorithm(
                                                                holder, functionality)));
    }
}
