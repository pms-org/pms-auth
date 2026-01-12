// package com.example.auth.util;

// import java.security.KeyPair;
// import java.security.KeyPairGenerator;
// import java.security.interfaces.RSAPrivateKey;
// import java.security.interfaces.RSAPublicKey;
// import java.util.UUID;

// import com.nimbusds.jose.jwk.RSAKey;

// public final class Jwks {

//     private Jwks() {}

//     public static RSAKey generateRsa() {
//         try {
//             KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
//             generator.initialize(2048);
//             KeyPair keyPair = generator.generateKeyPair();

//             return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
//                     .privateKey((RSAPrivateKey) keyPair.getPrivate())
//                     .keyID(UUID.randomUUID().toString())
//                     .build();
//         } catch (Exception e) {
//             throw new IllegalStateException(e);
//         }
//     }
// }
