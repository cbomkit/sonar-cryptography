package com.ibm.plugin.rules.detection.nodecrypto;

import javax.annotation.Nonnull;

class NodeCryptoRSATest extends NodeCryptoRuleTestBase {
    @Override
    @Nonnull
    protected String fixturePath() {
        return "rules/detection/nodecrypto/NodeCryptoRSATestFile.js";
    }
}
