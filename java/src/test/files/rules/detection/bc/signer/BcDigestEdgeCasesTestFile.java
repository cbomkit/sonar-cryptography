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
package com.ibm.plugin.rules.detection.bc.signer;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.WhirlpoolDigest;
import org.bouncycastle.crypto.digests.TigerDigest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;

public class BcDigestEdgeCasesTestFile {

    public static void test() {
        Digest whirlpool = new WhirlpoolDigest(); // Noncompliant {{(MessageDigest) Whirlpool}}

        Digest tiger = new TigerDigest(); // Noncompliant {{(MessageDigest) Tiger}}

        Digest ripemd = new RIPEMD160Digest(); // Noncompliant {{(MessageDigest) RIPEMD-160}}
    }
}
