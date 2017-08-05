# Java Crypto-Conditions [![join the chat on gitter][gitter-image]][gitter-url] [![circle-ci][circle-image]][circle-url] [![codecov][codecov-image]][codecov-url]

[gitter-image]: https://badges.gitter.im/interledger/java-crypto-conditions.svg
[gitter-url]: https://gitter.im/interledger/java-crypto-conditions
[circle-image]: https://circleci.com/gh/interledger/java-crypto-conditions.svg?style=shield
[circle-url]: https://circleci.com/gh/interledger/java-crypto-conditions
[codecov-image]: https://codecov.io/gh/interledger/java-crypto-conditions/branch/master/graph/badge.svg
[codecov-url]: https://codecov.io/gh/interledger/java-crypto-conditions


Java implementation of Crypto-Conditions (See [RFC](https://datatracker.ietf.org/doc/draft-thomas-crypto-conditions/)).

v2.0 implements the latest RFC (draft-02)

## Dependencies

This library uses various cryptographic functions so it relies on implementations of RSA and ED25519 signature schemes.

For RSA any provider that supports **SHA256withRSA/PSS** signatures can be used. The library has been tested with BouncyCastle v1.46 but has no runtime dependancy on it.

For ED25519 the library depends on [net.i2p.crypto.eddsa](https://github.com/str4d/ed25519-java). As there are no standard interfaces in the `java.security` namespace for EdDSA keys the library is included as a dependancy. Future versions will hopefully remove this dependency.

 
## Usage

### Requirements
This project uses Maven to manage dependencies and other aspects of the build.  
To install Maven, follow the instructions at [https://maven.apache.org/install.html](https://maven.apache.org/install.html).

### Get the code

``` sh
git clone https://github.com/interledger/java-crypto-conditions
cd java-crypto-conditions
```

### Build the Project
To build the project, execute the following command:

```bash
$ mvn clean install
```

#### Checkstyle
The project uses checkstyle to keep code style consistent. All Checkstyle checks are run by default during the build.

### Step 3: Use

#### PREIMAGE-SHA-256 Example:
~~~java
byte[] preimage = "Hello World!".getBytes(Charset.defaultCharset());
PreimageSha256Condition condition = new PreimageSha256Condition(preimage);

PreimageSha256Fulfillment fulfillment = new PreimageSha256Fulfillment(preimage);
if(fulfillment.validate(condition)) {
    System.out.println("Fulfillment is valid!");
}
~~~

#### THRESHOLD-SHA-256, ED25519-SHA-256 and RSA-SHA-256 Example:
~~~java
//Generate RSA-SHA-256 condition
KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA");
rsaKpg.initialize(new RSAKeyGenParameterSpec(2048, new BigInteger("65537")));
KeyPair rsaKeyPair = rsaKpg.generateKeyPair();

RsaSha256Condition condition = new RsaSha256Condition((RSAPublicKey) rsaKeyPair.getPublic());

//Generate ED25519-SHA-256 condition
net.i2p.crypto.eddsa.KeyPairGenerator edDsaKpg = new net.i2p.crypto.eddsa.KeyPairGenerator();
KeyPair edDsaKeyPair = edDsaKpg.generateKeyPair();
Signature edDsaSigner = new EdDSAEngine(sha512Digest);


PreimageSha256Fulfillment fulfillment = new PreimageSha256Fulfillment(preimage);
//Verify against empty message
if(fulfillment.verify(condition, new byte[0])) {
    System.out.println("Fulfillment is valid!");
}
~~~


#### Encoding Example:
~~~java
//Read a condition from a stream (InputStream in)
DERInputStream derStream = new DERInputStream(in);
Condition condition = CryptoConditionReader.readCondition(derStream);

//Read a fulfillment from a stream (InputStream in)
DERInputStream derStream = new DERInputStream(in);
Fulfillment fulfillment = CryptoConditionReader.readFulfillment(derStream);

//Read a condition from a byte array (byte[] buffer)
Condition condition = CryptoConditionReader.readCondition(buffer);

//Read a fulfillment from a byte array (byte[] buffer)
Fulfillment fulfillment = CryptoConditionReader.readFulfillment(buffer);

//Get binary encoding of condition that can be written to stream
byte[] binaryEncodedCondition = condition.getEncoded();

//Get binary encoding of fulfillment that can be written to stream
byte[] binaryEncodedCondition = fulfillment.getEncoded();

//Get ni: URI form for sharing via text-based protocols
URI uriEncodedCondition = condition.getUri();

~~~

## Contributors

Any contribution is very much appreciated! 

[![gitter][gitter-image]][gitter-url]

## TODO

  - More Unit tests
  - Finish implementing test runner for shared integration tests from [https://github.com/rfcs/crypto-conditions](https://github.com/rfcs/crypto-conditions).
  - Helper functions for generating fulfillments
  	- From private keys and messages
  	- Using a builder
  - Validate condition against a global max cost

## License

This code is released under the Apache 2.0 License. Please see [LICENSE](LICENSE) for the full text.
