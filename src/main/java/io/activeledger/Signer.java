package io.activeledger;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.util.encoders.Hex;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonWriter;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.security.spec.ECPublicKeySpec;

public class Signer {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public String sign(String privateKeyHex, String data) throws NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, NoSuchProviderException, InvalidKeyException, IOException {
//        PrivateKey key;
//        key = getPrivateKey(privateKeyHex);

        byte[] keyBytes = Hex.decode(privateKeyHex.replace("0x", ""));
        ECNamedCurveParameterSpec bcSpec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256k1");
        ECPrivateKeyParameters keyParams = new ECPrivateKeyParameters(
                new BigInteger(1, keyBytes),
                new ECDomainParameters(
                        bcSpec.getCurve(),
                        bcSpec.getG(),
                        bcSpec.getN(),
                        bcSpec.getH()
                )
        );

        String formattedData;
        formattedData = encodeJSON(data);

//        byte[] dataHash;
//        dataHash = hashData(formattedData);

//        byte[] keyBytes = Hex.decode(privateKeyHex.replace("0x", ""));

//        ECPrivateKeyParameters keyParams;
//        keyParams = (ECPrivateKeyParameters) PrivateKeyFactory.createKey(keyBytes);

        byte[] keyData;
        keyData = Hex.decode(privateKeyHex.replace("0x", ""));
        KeyFactory factory;
        factory = KeyFactory.getInstance("ECDSA", "BC");

        BigInteger keyInt;
        keyInt = new BigInteger(privateKeyHex.replace("0x", ""), 16);

        ECParameterSpec paramSpec;
        paramSpec = ECNamedCurveTable.getParameterSpec("secp256k1");

        ECPrivateKeySpec skSpec;
        skSpec = new ECPrivateKeySpec(keyInt, paramSpec);

        PrivateKey sk;
        sk = factory.generatePrivate(skSpec);

        Signature sign = Signature.getInstance("SHA256withECDSA", "BC");
        sign.initSign(sk);

        sign.update(formattedData.getBytes());
        byte[] signature;
        signature = sign.sign();

//        ECDSASigner signer;
//        signer = new ECDSASigner();
//
//        signer.init(true, keyParams);
//        BigInteger[] signatureComponents;
//        signatureComponents = signer.generateSignature(formattedData.getBytes());
//
//        byte[] r = toFixedLength(signatureComponents[0].toByteArray(), 32);
//        byte[] s = toFixedLength(signatureComponents[1].toByteArray(), 32);
//        byte[] signature = new byte[64];
//        System.arraycopy(r, 0, signature, 32 - r.length, r.length);
//        System.arraycopy(s, 0, signature, 64 - s.length, s.length);

        System.out.println("Data Hash: " + Hex.toHexString(formattedData.getBytes()));
        System.out.println("Signature: " + Base64.getEncoder().encodeToString(signature));

//        System.out.println("Sig: " + rawSig);

        String encodedSig;
        encodedSig = Base64.getEncoder().encodeToString(signature);

        return encodedSig;
    }

    public boolean verify(String publicKeyHex, String signature, String data) throws SignatureException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, InvalidKeyException {
//        PublicKey key;
//        key = getPublicKey(publicKeyHex);
        byte[] compressedKey = Hex.decode(publicKeyHex.replace("0x", ""));
        ECNamedCurveParameterSpec bcSpec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256k1");
        org.bouncycastle.math.ec.ECPoint point = bcSpec.getCurve().decodePoint(compressedKey);
        ECPublicKeyParameters publicKeyParams = new ECPublicKeyParameters(point, new ECDomainParameters(bcSpec.getCurve(), bcSpec.getG(), bcSpec.getN(), bcSpec.getH()));

        String formattedData;
        formattedData = encodeJSON(data);

//        byte[] dataHash;
//        dataHash = hashData(formattedData);

//        Signature ecVerify;
//        ecVerify = Signature.getInstance("SHA256withECDSA", "BC");
//        ecVerify.initVerify(key);
//        ecVerify.update(dataHash);
//
        byte[] signatureBytes;
        signatureBytes = Base64.getDecoder().decode(signature);

        byte[] r = new byte[32];
        byte[] s = new byte[32];
        System.arraycopy(signatureBytes, 0, r, 0, 32);
        System.arraycopy(signatureBytes, 32, s, 0, 32);
        BigInteger rBigInt = new BigInteger(1, r);
        BigInteger sBigInt = new BigInteger(1, s);

        ECDSASigner verifier = new ECDSASigner();
        verifier.init(false, publicKeyParams);

        System.out.println("Data Hash (Verify): " + Hex.toHexString(formattedData.getBytes()));
        System.out.println("Signature (Verify): " + Base64.getEncoder().encodeToString(signatureBytes));

        boolean isValid;
        isValid = verifier.verifySignature(formattedData.getBytes(), rBigInt, sBigInt);

        return isValid;
    }

   // private PrivateKey getPrivateKey(String keyHex) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
   //     keyHex = keyHex.replace("0x", "");

   //     byte[] keyBytes;
   //     keyBytes = Hex.decode(keyHex);

   //     ECNamedCurveParameterSpec bcSpec;
   //     bcSpec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256k1");

   //     EllipticCurve curve;
   //     curve = new EllipticCurve(
   //             new ECFieldFp(bcSpec.getCurve().getField().getCharacteristic()),
   //             bcSpec.getCurve().getA().toBigInteger(),
   //             bcSpec.getCurve().getB().toBigInteger()
   //     );

   //     java.security.spec.ECPoint gPoint;
   //     gPoint = new java.security.spec.ECPoint(
   //             bcSpec.getG().getAffineXCoord().toBigInteger(),
   //             bcSpec.getG().getAffineYCoord().toBigInteger()
   //     );

   //     ECParameterSpec spec = new ECParameterSpec(
   //             curve,
   //             gPoint,
   //             bcSpec.getN(),
   //             bcSpec.getH().intValue()
   //     );

   //     ECPrivateKeySpec keySpec;
   //     keySpec = new ECPrivateKeySpec(
   //             new BigInteger(1, keyBytes),
   //             spec
   //     );

   //     KeyFactory factory;
   //     factory = KeyFactory.getInstance("ECDSA", "BC");

   //     PrivateKey privateKey;
   //     privateKey = factory.generatePrivate(keySpec);

   //     return privateKey;
   // }


   // private PublicKey getPublicKey(String keyHex) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
   //     keyHex = keyHex.replace("0x", "");

   //     byte[] compressedKey;
   //     compressedKey = Hex.decode(keyHex);

   //     ECNamedCurveParameterSpec spec;
   //     spec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256k1");

   //     org.bouncycastle.math.ec.ECPoint point;
   //     point = spec.getCurve().decodePoint(compressedKey);
   //     point = point.normalize();

   //     java.security.spec.ECPoint javaPoint;
   //     javaPoint = new java.security.spec.ECPoint(
   //             point.getAffineXCoord().toBigInteger(),
   //             point.getAffineYCoord().toBigInteger()
   //     );

   //     ECPublicKeySpec keySpec;
   //     keySpec = new ECPublicKeySpec(javaPoint, new ECNamedCurveSpec(
   //             "secp256k1",
   //             spec.getCurve(),
   //             spec.getG(),
   //             spec.getN()
   //     ));

   //     KeyFactory factory;
   //     factory = KeyFactory.getInstance("ECDSA", "BC");

   //     PublicKey key;
   //     key = factory.generatePublic(keySpec);

// //       System.out.println("Public Key\n" +  key.toString());

   //     return key;
   // }

    private String encodeJSON(String data) {
        data = data.trim();

        JsonReader reader;
        reader = Json.createReader(new StringReader(data));

        JsonObject object;
        object = reader.readObject();

        StringWriter writer;
        writer = new StringWriter();

        JsonWriter jsonWriter;
        jsonWriter = Json.createWriter(writer);

        jsonWriter.write(object);

        String jsonString;
        jsonString = writer.toString();

        return jsonString;
    }

    private byte[] hashData(String data) throws NoSuchAlgorithmException {
        MessageDigest sha256;
        sha256 = MessageDigest.getInstance("SHA-256");

        byte[] dataHash;
        dataHash = sha256.digest(data.getBytes());

        return dataHash;
    }

    private byte[] toFixedLength(byte[] src, int length) {
        byte[] dest = new byte[length];
        if (src.length <= length) {
            System.arraycopy(src, 0, dest, length - src.length, src.length);
        } else {
            System.arraycopy(src, src.length - length, dest, 0, length);
        }
        return dest;
    }

}
