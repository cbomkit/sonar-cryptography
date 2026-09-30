/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2025 PQCA
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
package com.ibm.engine.language.cpp;

/**
 * Marker interface for C/C++ detection rules.
 *
 * <p>This interface fills the {@code R} (Rule) generic type parameter used throughout the engine.
 * It is the C/C++ equivalent of {@code JavaCheck} in the Java language support and {@code
 * CSharpCheck} in the C# language support.
 *
 * <p>All C/C++ detection rule classes should implement this interface so that the engine's generic
 * machinery can operate in a type-safe way across language modules.
 */
public interface CppCheck {
    // Marker interface — no methods required.
    // The engine uses this as a type bound: IDetectionRule<CppTree>,
    // ILanguageSupport<CppCheck, CppTree, CppSymbol, CppScanContext>, etc.
}
