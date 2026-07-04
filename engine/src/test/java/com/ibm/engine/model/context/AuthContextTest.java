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
package com.ibm.engine.model.context;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class AuthContextTest {

    @Test
    void carriesKindAndType() {
        final AuthContext context = new AuthContext(AuthContext.Kind.JWT);
        assertThat(context.kind()).isEqualTo(AuthContext.Kind.JWT);
        assertThat(context.type()).isEqualTo(AuthContext.class);
        assertThat(context.is(AuthContext.class)).isTrue();
    }

    @Test
    void defaultsToNone() {
        assertThat(new AuthContext().kind()).isEqualTo(AuthContext.Kind.NONE);
    }
}
