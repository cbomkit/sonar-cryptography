package com.ibm.plugin.rules.detection.nodecrypto;

import javax.annotation.Nonnull;

class NodeCryptoKeyGenTest extends NodeCryptoRuleTestBase {
    @Override
    @Nonnull
    protected String fixturePath() {
        return "rules/detection/nodecrypto/NodeCryptoKeyGenTestFile.js";
    }
}
