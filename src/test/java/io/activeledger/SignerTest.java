package io.activeledger;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SignerTest {

    @Test
    public void testSignAndVerify() throws Exception {
        KeyGenerator gen = new KeyGenerator();
        ALKeyPair pair = gen.generate();

        System.out.println("Public Key: " + pair.getPublic() + "\n");
        System.out.println("Private Key: " + pair.getPrivate() + "\n");

        String data = "{\"tx\": \"Hello world\"}";
        Signer signer = new Signer();

        String sig = signer.sign(pair.getPrivate(), data);

        assertNotNull(sig);

        System.out.println("Signature: " + sig);

        boolean isValid = signer.verify(pair.getPublic(), sig, data);
        assertTrue(isValid);
    }

    @Test
    public void testSignTransaction() throws Exception {
        KeyGenerator gen = new KeyGenerator();
        ALKeyPair pair = gen.generate();

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
        String sig = signer.sign(pair.getPrivate(), data);

        assertNotNull(sig);

        System.out.println("Transaction: \n" + data);
        System.out.println("Private key: " + pair.getPrivate());
        System.out.println("Public key: " + pair.getPublic());
        System.out.println("Signature: " + sig);

        boolean isValid = signer.verify(pair.getPublic(), sig, data);
        assertTrue(isValid);
    }

    @Test
    public void testNumerousKeys() throws Exception {
        KeyGenerator g = new KeyGenerator();

        for (var i = 0; i < 20; i++) {
            ALKeyPair pair = g.generate();

            System.out.println("Key " + (i + 1) + " Public: " + pair.getPublic());
        }
    }

}