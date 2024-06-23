package io.activeledger;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SignerTest {

    @Test
    public void testSignAndVerify() throws Exception {
        KeyGenerator gen = new KeyGenerator();
        KeyPair pair = gen.generate();

        String data = "Hello world";
        Signer signer = new Signer();

        String sig = signer.sign(pair.getPrivate(), data);

        assertNotNull(sig);

        System.out.println("Base64 Signature: " + sig);

        boolean isValid = signer.verify(pair.getPublic(), sig, data);
        assertTrue(isValid);
    }

    @Test
    public void testSignAndVerifyHex() throws Exception {
        KeyGenerator gen = new KeyGenerator();
        KeyPair pair = gen.generate();

        String data = "Hello world";
        Signer signer = new Signer();

        String sig = signer.signHex(pair.getPrivate(), data);

        assertNotNull(sig);

        System.out.println("Hex Signature: " + sig);

        boolean isValid = signer.verifyHex(pair.getPublic(), sig, data);
        assertTrue(isValid);
    }

    @Test
    public void testSignTransaction() throws Exception {
        KeyGenerator gen = new KeyGenerator();
        KeyPair pair = gen.generate();

        String data = """
                {
                        "$namespace": "default",
                        "$contract": "onboard",
                        "$i": {
                            "identity": {
                            	"type":"secp256k1",
                                "publicKey": "%s"
                            }
                        }
                    }
                """.formatted(pair.getPublic());

        Signer signer = new Signer();
        String sigHex = signer.signHex(pair.getPrivate(), data);
        String sigB64 = signer.sign(pair.getPrivate(), "data");

        assertNotNull(sigB64);
        assertNotNull(sigHex);

        System.out.println("Transaction: \n" + data);
        System.out.println("Hex Signature: " + sigHex);
        System.out.println("B64 Signature: " + sigB64);
    }

}