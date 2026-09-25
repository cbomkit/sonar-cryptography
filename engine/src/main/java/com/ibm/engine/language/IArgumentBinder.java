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
package com.ibm.engine.language;

import com.ibm.engine.rule.DetectionRule;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nonnull;

/** Matches and binds a call's arguments without recording detections. */
public interface IArgumentBinder<T> {
    /**
     * Returns expressions keyed by declared parameter index. An absent or wrong-type optional
     * parameter has no entry; an unmatched required parameter rejects the entire call. A present
     * result may contain no entries if all declared parameters are optional and absent.
     *
     * @param rule the rule declaring the parameters
     * @param call the language-specific call to bind
     * @return the complete binding if the call matches, otherwise empty
     */
    @Nonnull
    Optional<Map<Integer, T>> bind(@Nonnull DetectionRule<T> rule, @Nonnull T call);
}
