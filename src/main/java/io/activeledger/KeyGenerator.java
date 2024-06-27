package io.activeledger;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import java.security.*;
import java.security.interfaces.ECPrivateKey;
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
//        prvKey = "0x" + Hex.toHexString(rawPair.getPrivate().getEncoded());
        prvKey = "0x" + getPrivateKey(rawPair.getPrivate());

        String pubKey;
        pubKey = "0x" + compressPublicKey(rawPair.getPublic());
//        System.out.println("Private key hex: " + prvKey);
//        System.out.println("Public key hex: " + pubKey);

//        System.out.println("Private Key\n" + rawPair.getPrivate().toString());
//        System.out.println("Public Key\n" +  rawPair.getPublic().toString());

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

//        String unpadded;
//        unpadded = removePadding(hex);

        return hex;
    }

    private String compressPublicKey(PublicKey key) {
        ECPoint q = ((org.bouncycastle.jce.interfaces.ECPublicKey) key).getQ().normalize();

        byte[] compressed = q.getEncoded(true);
        return Hex.toHexString(compressed);
    }

    private String removePadding(String paddedKey) {
        String key;
        key = paddedKey.replaceFirst("^0+(?!$)", "");

        return key;
    }
}
