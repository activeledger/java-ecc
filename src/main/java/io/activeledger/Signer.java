package io.activeledger;

import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

import java.math.BigInteger;
import java.security.SignatureException;
import java.util.Base64;

public class Signer {

    public String sign(String privateKey, String data) {
        ECKeyPair pair;
        pair = getPair(privateKey);

        byte[] rawSig;
        rawSig = createSignature(pair, data);

        String encodedSig;
        encodedSig = Base64.getEncoder().encodeToString(rawSig);

        return encodedSig;
    }

    public String signHex(String privateKey, String data) {
        ECKeyPair pair;
        pair = getPair(privateKey);

        byte[] rawSig;
        rawSig = createSignature(pair, data);

        String encodedSig;
        encodedSig = "0x" + Numeric.toHexString(rawSig);
        return encodedSig;
    }

    public boolean verify(String publicKey, String signature, String data) throws SignatureException {
        byte[] sigDecoded;
        sigDecoded = Base64.getDecoder().decode(signature);

        String recoveredKey;
        recoveredKey = recoverAndCompress(sigDecoded, data);

        boolean isValid;
        isValid = publicKey.equalsIgnoreCase(recoveredKey);
        return isValid;
    }

    public boolean verifyHex(String publicKey, String signature, String data) throws SignatureException {
        byte[] sigBytes = Numeric.hexStringToByteArray(
                signature.replace("0x", "")
        );

        String recoveredKey;
        recoveredKey = recoverAndCompress(sigBytes, data);

        boolean isValid;
        isValid = publicKey.equalsIgnoreCase(recoveredKey);

        return isValid;
    }

    private String recoverAndCompress(byte[] signature, String data) throws SignatureException {
        Sign.SignatureData signatureData = new Sign.SignatureData(
                new byte[]{signature[signature.length - 1]},
                copyOfRange(signature, 0, 32),
                copyOfRange(signature, 32, 64)
        );

        String recoveredPubKey;
        recoveredPubKey = Numeric.toHexStringNoPrefix(Sign.signedMessageToKey(data.getBytes(), signatureData));

        String compressedRecoveredPubKey;
        compressedRecoveredPubKey = compressPublicKey(recoveredPubKey);

        String finalKey;
        finalKey = "0x" + compressedRecoveredPubKey;
        return  finalKey;

    }

    private ECKeyPair getPair(String privateKey) {
        BigInteger key;
        key = Numeric.toBigInt(privateKey);

        ECKeyPair pair;
        pair = ECKeyPair.create(key);

        return pair;
    }

    private byte[] createSignature(ECKeyPair pair, String data) {
        Sign.SignatureData signatureData;
        signatureData = Sign.signMessage(data.getBytes(), pair);

        byte[] r, s, signature;
        r = signatureData.getR();
        s = signatureData.getS();
        signature = new byte[r.length + s.length + 1];

        System.arraycopy(r, 0, signature, 0, r.length);
        System.arraycopy(s, 0, signature, r.length, s.length);

        signature[signature.length - 1] = signatureData.getV()[0];

        return signature;
    }

    private String compressPublicKey(String uncompressedKey) {
        String x = uncompressedKey.substring(0, 64);
        String y = uncompressedKey.substring(64, 128);

        int yInt = Integer.parseInt(y.substring(63), 16);
        boolean isEven =  (yInt & 1) == 0;
        int prefix = isEven ? 0x02 : 0x03;

        return String.format("%02x", prefix) + x;
    }

    private static byte[] copyOfRange(byte[] source, int from, int to) {
        byte[] range;
        range = new byte[to - from];

        System.arraycopy(source, from, range, 0, range.length);

        return range;
    }
}
