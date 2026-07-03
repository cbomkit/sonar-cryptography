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

import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.rules.AeadBlockCipherReorganizer;
import com.ibm.mapper.reorganizer.rules.AsymmetricBlockCipherReorganizer;
import com.ibm.mapper.reorganizer.rules.BlockCipherReorganizer;
import com.ibm.mapper.reorganizer.rules.CipherParameterReorganizer;
import com.ibm.mapper.reorganizer.rules.CipherSuiteReorganizer;
import com.ibm.mapper.reorganizer.rules.KeyReorgenizer;
import com.ibm.mapper.reorganizer.rules.MacReorganizer;
import com.ibm.mapper.reorganizer.rules.SignatureReorganizer;
import java.util.List;
import javax.annotation.Nonnull;

public final class JavaReorganizerRules {
    private JavaReorganizerRules() {
        // private
    }

    @Nonnull
    public static List<IReorganizerRule> rules() {
        return List.of(
                AeadBlockCipherReorganizer.MERGE_AE_PARENT_AND_CHILD,
                AeadBlockCipherReorganizer.MOVE_TAG_LENGTH_UNDER_MAC,
                AsymmetricBlockCipherReorganizer.INVERT_DIGEST_AND_ITS_SIZE,
                AsymmetricBlockCipherReorganizer.MERGE_PKE_PARENT_AND_CHILD,
                BlockCipherReorganizer.DEDUPLICATE_OVERLAPPING_ROOTS,
                BlockCipherReorganizer.MERGE_BLOCK_CIPHER_PARENT_AND_CHILD,
                CipherParameterReorganizer.MOVE_KEY_LENGTH_UNDER_TAG_LENGTH_UP,
                CipherParameterReorganizer.MOVE_NODES_UNDER_DECRYPT_UP,
                CipherParameterReorganizer.MOVE_NODES_UNDER_ENCRYPT_UP,
                CipherSuiteReorganizer.ADD_TLS_PROTOCOL_AS_PARENT_NODE,
                MacReorganizer.MERGE_UNKNOWN_MAC_PARENT_AND_CIPHER_CHILD,
                MacReorganizer.MOVE_SOME_MAC_CHILDREN_UNDER_BLOCKCIPHER,
                MacReorganizer.MOVE_TAG_LENGTH_UNDER_MAC,
                SignatureReorganizer.MERGE_UNKNOWN_SIGNATURE_PARENT_AND_CHILD,
                SignatureReorganizer.moveNodesFromUnderFunctionalityUnderParent(
                        Sign.class, Signature.class),
                SignatureReorganizer.MERGE_SIGNATURE_PARENT_AND_CHILD,
                KeyReorgenizer.SPECIFY_KEY_TYPE_BY_LOOKING_AT_KEY_GENERATION,
                KeyReorgenizer.MOVE_KEY_UNDER_ALGORITHM_AND_REPLACE_INNER_ALGORITHM,
                KeyReorgenizer.PROPAGATE_KEY_LENGTH_TO_BLOCK_CIPHER);
    }
}
