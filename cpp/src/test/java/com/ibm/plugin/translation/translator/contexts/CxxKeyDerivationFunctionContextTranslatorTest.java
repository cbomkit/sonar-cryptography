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

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.KeyDerivationFunctionContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.PBKDF2;
import com.ibm.mapper.model.algorithms.SSHKDF;
import com.ibm.mapper.model.algorithms.TLSPRF;
import com.ibm.mapper.utils.DetectionLocation;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class CxxKeyDerivationFunctionContextTranslatorTest {

    private static final DetectionLocation TEST_LOCATION =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "OpenSSL");

    private final CxxKeyDerivationFunctionContextTranslator translator =
            new CxxKeyDerivationFunctionContextTranslator();

    private Optional<INode> translate(String value) {
        return translator.translate(
                () -> "OpenSSL",
                new ValueAction<>(value, (AstNode) null),
                new KeyDerivationFunctionContext(),
                TEST_LOCATION);
    }

    @Test
    void tls1PrfIsNotMappedToPbkdf2() {
        Optional<INode> node = translate("TLS1-PRF-SHA256");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(TLSPRF.class).isNotInstanceOf(PBKDF2.class);
        assertThat(node.get().asString()).isEqualTo("TLS-PRF-SHA-256");
    }

    @Test
    void sshkdfIsNotMappedToPbkdf2() {
        Optional<INode> node = translate("SSHKDF-SHA256");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(SSHKDF.class).isNotInstanceOf(PBKDF2.class);
        assertThat(node.get().asString()).isEqualTo("SSHKDF-SHA-256");
    }
}
