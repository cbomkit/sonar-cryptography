package com.ibm.plugin.rules.detection.nodecrypto;

import javax.annotation.Nonnull;

class NodeCryptoTLSTest extends NodeCryptoRuleTestBase {
    @Override
    @Nonnull
    protected String fixturePath() {
        return "rules/detection/nodecrypto/NodeCryptoTLSTestFile.js";
    }
}
