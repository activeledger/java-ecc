package io.activeledger;

public class ALKeyPair {
    private final String privateKey;
    private final String publicKey;

    public ALKeyPair(String privateKey, String publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public String getPrivate() {
        return privateKey;
    }

    public String getPublic() {
        return publicKey;
    }
}
