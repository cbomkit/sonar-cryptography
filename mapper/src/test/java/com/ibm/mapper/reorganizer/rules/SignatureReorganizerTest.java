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
package com.ibm.mapper.reorganizer.rules;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.ibm.mapper.ITranslator;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.ProbabilisticSignatureScheme;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.RSAssaPSS;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.reorganizer.Reorganizer;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class SignatureReorganizerTest {

    private final DetectionLocation location = mock(DetectionLocation.class);

    @Test
    void aSigningOperationWithoutSchemeIsASignatureOfAnUnknownScheme() {
        // X509_sign(cert, pkey, EVP_sha256()) with a key whose type is not known
        final Sign sign = new Sign(location);
        sign.put(new SHA2(256, location));

        final List<INode> result =
                new Reorganizer(
                                List.of(
                                        SignatureReorganizer
                                                .MAKE_SIGNATURE_OF_A_SIGNING_OPERATION_WITHOUT_SCHEME))
                        .reorganize(new ArrayList<>(List.of(sign)));

        assertThat(result)
                .singleElement()
                .satisfies(
                        signature -> {
                            assertThat(signature.is(Signature.class)).isTrue();
                            assertThat(signature.asString()).isEqualTo(ITranslator.UNKNOWN);
                            assertThat(signature.hasChildOfType(Sign.class)).containsSame(sign);
                            assertThat(signature.hasChildOfType(MessageDigest.class)).isPresent();
                            assertThat(sign.getChildren()).isEmpty();
                        });
    }

    @Test
    void aSigningOperationNamingItsSchemeIsASignatureOfThatScheme() {
        // EVP_DigestSignInit(mdctx, &pctx, md, NULL, pkey);
        // EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING)
        final Sign sign = new Sign(location);
        final RSAssaPSS pss = new RSAssaPSS(location);
        sign.put(pss);
        sign.put(new SHA2(256, location));

        final List<INode> result =
                new Reorganizer(
                                List.of(
                                        SignatureReorganizer
                                                .MAKE_SIGNATURE_OF_A_SIGNING_OPERATION_WITHOUT_SCHEME))
                        .reorganize(new ArrayList<>(List.of(sign)));

        assertThat(result).singleElement().isSameAs(pss);
        assertThat(pss.is(ProbabilisticSignatureScheme.class)).isTrue();
        assertThat(pss.hasChildOfType(Sign.class)).containsSame(sign);
        assertThat(pss.hasChildOfType(MessageDigest.class)).isPresent();
    }
}
