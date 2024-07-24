package io.activeledger;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
//import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.util.encoders.Hex;
//import org.bouncycastle.math.ec.ECPoint;

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
import java.util.Arrays;
import java.util.Base64;

public class Signer {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public String sign(String privateKeyHex, String data) throws NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, NoSuchProviderException, InvalidKeyException, IOException {
        // Need to make sure that the JSON data matches what Activeledger expects otherwise
        // verification will fail.
        String formattedData;
        formattedData = encodeJSON(data);

        PrivateKey sk;
        sk = ALPrivateKey.hexToPrivateKey(privateKeyHex);

        Signature sign = Signature.getInstance("SHA256withECDSA", "BC");
        sign.initSign(sk);

        sign.update(formattedData.getBytes());
        byte[] signature;
        signature = sign.sign();

        String encodedSig;
        encodedSig = Base64.getEncoder().encodeToString(signature);

        return encodedSig;
    }

    // Temporarily private until verification works, signing confirmed working by running tx against Activeledger
    private boolean verify(String publicKeyHex, String signature) throws SignatureException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, InvalidKeyException, InvalidParameterSpecException {
        PublicKey pk;
        pk = ALPublicKey.hexToPublicKey(publicKeyHex);

        byte[] signatureBytes;
        signatureBytes = Base64.getDecoder().decode(signature);

        Signature signer;
        signer = Signature.getInstance("SHA256withECDSA", "BC");

        signer.initVerify(pk);

        boolean isValid;
        isValid = signer.verify(signatureBytes);

        return isValid;
    }

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
}
