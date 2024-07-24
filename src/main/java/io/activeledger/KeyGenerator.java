package io.activeledger;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class KeyGenerator {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public ALKeyPair generate() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator generator;
        generator = KeyPairGenerator.getInstance("ECDSA", "BC");

        ECGenParameterSpec spec;
        spec = new ECGenParameterSpec("secp256k1");

        generator.initialize(spec, new SecureRandom());

        KeyPair rawPair;
        rawPair = generator.generateKeyPair();

        String prvKey;
        prvKey = "0x" + getPrivateKey(rawPair.getPrivate());

        String pubKey;
        pubKey = "0x" + compressPublicKey(rawPair.getPublic());

        ALKeyPair pair;
        pair = new ALKeyPair(prvKey, pubKey);

        return pair;
    }

    private String getPrivateKey(PrivateKey privateKey) {
        BCECPrivateKey key;
        key = (BCECPrivateKey) privateKey;

        byte[] keyBytes;
        keyBytes = key.getD().toByteArray();

        String hex;
        hex = Hex.toHexString(keyBytes);

        return hex;
    }

    private String compressPublicKey(PublicKey key) {
        ECPoint q = ((org.bouncycastle.jce.interfaces.ECPublicKey) key).getQ().normalize();

        byte[] compressed = q.getEncoded(true);
        return Hex.toHexString(compressed);
    }
}
