package io.activeledger;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class KeyGeneratorTest {

    @Test
    @DisplayName("Generate key pair")
    public void testGenerateKeys() throws Exception {
        KeyGenerator keyGen = new KeyGenerator();
        KeyPair pair = keyGen.generate();

        assertNotNull(pair.getPrivate());
        assertNotNull(pair.getPublic());

        System.out.println("Private Key: " + pair.getPrivate());
        System.out.println("Public Key: " + pair.getPublic());
    }

}