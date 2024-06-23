package io.activeledger;

import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Keys;
import org.web3j.utils.Numeric;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class KeyGenerator {

    public KeyPair generate() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        ECKeyPair keyPair = generateKeyPair();

        String privateKeyHex = "0x" + keyPair.getPrivateKey().toString(16);
        String publicKeyHex = getCompressedPublicKey(keyPair);

        KeyPair pair;
        pair = new KeyPair(privateKeyHex, publicKeyHex);
        return pair;
    }

    private ECKeyPair generateKeyPair() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        ECKeyPair ecKeyPair;
        ecKeyPair = Keys.createEcKeyPair();
        return ecKeyPair;
    }

    private String getCompressedPublicKey(ECKeyPair keyPair) {
        String hex = Numeric.toHexStringWithPrefixZeroPadded(keyPair.getPublicKey(), 128);
        String compressed = compressPublicKey(hex);
        return "0x" + compressed;
    }

    private String compressPublicKey(String hex) {
        String x = hex.substring(2, 66);
        String y = hex.substring(66, 130);

        int yInt = Integer.parseInt(y.substring(63), 16);
        boolean isEven =  (yInt & 1) == 0;
        int prefix = isEven ? 0x02 : 0x03;

        return String.format("%02x", prefix) + x;
    }
}
