/*
 * SonarQube Cryptography Plugin
 * Copyright (C) 2024 IBM
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
package com.ibm.plugin.rules.detection.bc.mac;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;

public class BcCMacTestFile {
    public byte[] generateCMac(byte[] key, byte[] data) throws Exception {
        // Using AES engine with a 128-bit MAC size
        Mac mac = new CMac(new AESEngine(), 128); // Noncompliant {{(Mac) CMAC-AES}}
        // Noncompliant@-1 {{(BlockCipher) AES}}

        CipherParameters params = new KeyParameter(key);
        mac.init(params);

        mac.update(data, 0, data.length);

        byte[] output = new byte[mac.getMacSize()];
        mac.doFinal(output, 0);

        return output;
    }
}
