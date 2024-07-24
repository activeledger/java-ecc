<img src="https://www.activeledger.io/wp-content/uploads/2018/09/Asset-23.png" alt="Activeledger" width="500"/>

# Activeledger - Java ECC SDK
The Activeledger Java ECC SDK has been built to provide an easy way to generate an ECC keypair that can be used to sign transactions to be 
sent to the Activeledger network.

### Activeledger

[Visit Activeledger.io](https://activeledger.io/)

[Read Activeledgers documentation](https://github.com/activeledger/activeledger)

## Installation

```
```

## Usage

The SDK currently supports the following functions:
* Generate a new ECC keypair
* Sign a string using the generated private key

### Generate a new ECC keypair

The generate method returns an array containing the public and private keys as HEX strings.

```java
import io.activeledger.ALKeyPair;
import io.activeledger.KeyGenerator;

class MyClass {
    private void myMethod() {
        ALKeyPair pair;
        pair = this.generate();
        
        String prv, pub;
        prv = pair.getPrivate();
        pub = pair.getPublic();
        
        System.out.println("Private key HEX: " + prv + "\n");
        System.out.println("Public key HEX: " + pub + "\n");
    }
    
    private ALKeyPair generate() {
        KeyGenerator generator;
        generator = new KeyGenerator();
        
        ALKeyPair pair;
        pair = generator.generate();
        
        return pair;
    }
}
```

### Sign a string using a private key

The sign method takes two parameters: the private key as a HEX string, and the data to be signed also as a string.

**Note:** The data must be JSON.

```java
import io.activeledger.Signer;

class MyClass {
    private void getSignature(String privateKeyHex, String data) {
        Signer signer;
        signer = new Signer();
        
        String signature;
        signature = signer.sign(privateKeyHex, data);
        
        System.out.println("Signature: " + signature + "\n");
    }
}
```

## License

---

This project is licensed under the [MIT](https://github.com/activeledger/activeledger/blob/master/LICENSE) License
