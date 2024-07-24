package io.activeledger;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;

class ALPrivateKey {
    public static PrivateKey hexToPrivateKey(String hex) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        hex = hex.replace("0x", "");

        KeyFactory factory;
        factory = KeyFactory.getInstance("ECDSA", "BC");

        BigInteger keyInt;
        keyInt = new BigInteger(hex, 16);

        ECParameterSpec paramSpec;
        paramSpec = ECNamedCurveTable.getParameterSpec("secp256k1");

        ECPrivateKeySpec skSpec;
        skSpec = new ECPrivateKeySpec(keyInt, paramSpec);

        PrivateKey sk;
        sk = factory.generatePrivate(skSpec);

        return sk;
    }
}
