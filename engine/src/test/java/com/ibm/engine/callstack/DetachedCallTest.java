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
package com.ibm.engine.callstack;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.ibm.engine.detection.IType;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.sonar.api.batch.fs.InputFile;

class DetachedCallTest {

    @Test
    void holdsNoTreeAndExposesKeys() {
        DetachedScanContext<Object, Object> ctx =
                new DetachedScanContext<>(mock(InputFile.class), "/p/CrossFileUsage.java", null);
        IType owner = mock(IType.class);

        DetachedCall<Object, Object> call =
                new DetachedCall<>(owner, "make", List.of(), List.of(), ctx);

        assertThat(call.tree()).isNull();
        assertThat(call.publisher()).isSameAs(ctx);
        assertThat(call.invokedObjectType()).isSameAs(owner);
        assertThat(call.methodName()).isEqualTo("make");
        assertThat(call.arguments()).isEmpty();
    }
}
