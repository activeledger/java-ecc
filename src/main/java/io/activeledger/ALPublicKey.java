package io.activeledger;

import org.bouncycastle.jce.ECPointUtil;

import java.security.*;
import java.security.spec.*;

class ALPublicKey {
    public static PublicKey hexToPublicKey(String hex) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException, InvalidParameterSpecException {

        AlgorithmParameters aParams;
        aParams = AlgorithmParameters.getInstance("EC", "BC");
        aParams.init(new ECGenParameterSpec("secp256k1"));

        ECParameterSpec params;
        params = aParams.getParameterSpec(ECParameterSpec.class);

        ECPoint point;
        point = ALPublicKey.getPoint(hex, params);

        ECPublicKeySpec keySpec;
        keySpec = new ECPublicKeySpec(point, params);

        KeyFactory factory;
        factory = KeyFactory.getInstance("ECDSA", "BC");

        PublicKey pk;
        pk = factory.generatePublic(keySpec);

        return pk;
    }

    private static ECPoint getPoint(String hex, ECParameterSpec spec) throws InvalidKeyException {
        hex = hex.replace("0x", "");

        byte[] bytes;
        bytes = new byte[hex.length() / 2];

        for (int i = 0; i < hex.length(); i += 2) {
            String sub;
            sub = hex.substring(i, i + 2);

            int intVal;
            intVal = Integer.parseInt(sub, 16);

            bytes[i/2] = (byte) intVal;
        }

        ECPoint point;
        point = ECPointUtil.decodePoint(spec.getCurve(), bytes);

        return point;

    }
}
