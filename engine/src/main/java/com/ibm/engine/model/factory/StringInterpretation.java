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
package com.ibm.engine.model.factory;

/**
 * Describes how a resolved {@link String} is turned into a size by a {@link SizeFactory}. It only
 * applies to string values; resolved integers are always interpreted using the factory's {@link
 * com.ibm.engine.model.Size.UnitType}.
 */
public enum StringInterpretation {
    /**
     * The string holds a number (e.g. {@code "256"}). The factory's unit type applies to the parsed
     * value. Invalid or overflowing input yields no size; there is no fallback to {@link
     * #BYTE_LENGTH}.
     */
    NUMERIC_VALUE,
    /**
     * The string is content (e.g. key material). Its size is the number of bytes it occupies,
     * converted to bits. The factory's unit type is not used.
     */
    BYTE_LENGTH
}
