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
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.rules.KeyAgreementReorganizer;
import com.ibm.mapper.reorganizer.rules.KeyDerivationReorganizer;
import com.ibm.mapper.reorganizer.rules.PaddingReorganizer;
import com.ibm.mapper.reorganizer.rules.SignatureReorganizer;

import javax.annotation.Nonnull;
import java.util.List;
import java.util.stream.Stream;

public final class GoReorganizerRules {

    private GoReorganizerRules() {
        // private
    }

    @Nonnull
    public static List<IReorganizerRule> rules() {
        return Stream.of(
                        SignatureReorganizer.moveFunctionalityUnderChildNode(
                                Sign.class, Signature.class),
                        SignatureReorganizer.moveNodesFromUnderFunctionalityUnderNode(
                                Sign.class, PublicKeyEncryption.class),
                        SignatureReorganizer.moveNodesFromUnderFunctionalityUnderNode(
                                Sign.class, Signature.class),
                        SignatureReorganizer.MERGE_SIGNATURE_PARENT_AND_CHILD,
                        SignatureReorganizer.MERGE_SIGNATURE_WITH_PKE_UNDER_PRIVATE_KEY,
                        SignatureReorganizer.MOVE_PSS_FROM_UNDER_SIGN_FUNCTION_TO_UNDER_KEY,
                        SignatureReorganizer.MAKE_RSA_TO_SIGNATURE,
                        KeyDerivationReorganizer.moveModeFromParentToNode(BlockCipher.class),
                        KeyDerivationReorganizer.moveModeFromParentToNode(MessageDigest.class),
                        KeyAgreementReorganizer.MERGE_KEYAGREEMENT_WITH_PKE_UNDER_PRIVATE_KEY,
                        PaddingReorganizer.MOVE_OAEP_UNDER_ALGORITHM)
                .toList();
    }
}
