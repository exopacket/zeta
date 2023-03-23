package com.inteliense.zeta.utils;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSA {

    public static PublicKey publicKeyFromStr(String pubKey) {

        try {

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec keySpec = new X509EncodedKeySpec(EncodingUtils.fromBase64(pubKey));
            return keyFactory.generatePublic(keySpec);

        } catch (Exception ex) {

            ex.printStackTrace();

        }

        return null;

    }

    public static PrivateKey privateKeyFromStr(String privateKey) {

        try {

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(EncodingUtils.fromBase64(privateKey));
            return keyFactory.generatePrivate(keySpec);

        } catch (Exception ex) {

            ex.printStackTrace();

        }

        return null;

    }

    public static KeyPair generateKeyPair() {

        try {

            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            return gen.generateKeyPair();

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;

    }

    public static String encrypt(String input, PublicKey publicKey) {

        try {

            byte[] key = Random.generateKey(256);
            byte[] iv = Random.generateIv(96);
            byte[] random = new byte[key.length  + iv.length];

            int x = 0;
            for(int i=0; i< random.length; i++) {
                if(i>=key.length) {
                    random[i] = iv[x];
                    x++;
                } else {
                    random[i] = key[i];
                }
            }

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] encryptedKey = cipher.doFinal(random);
            byte[] encryptedPayload = AES.gcm(input.getBytes("UTF-8"), key, iv, null, true);
            byte[] result = new byte[encryptedKey.length + encryptedPayload.length];
            x = 0;
            for(int i=0; i<result.length; i++) {
                if(i >= encryptedKey.length) {
                    result[i] = encryptedPayload[x];
                    x++;
                } else {
                    result[i] = encryptedKey[i];
                }
            }

            return Base64.getEncoder().encodeToString(result);

        } catch (Exception ex) {

            ex.printStackTrace();

        }

        return "";

    }

    public static String decrypt(String input, PrivateKey privateKey) {

        try {

            byte[] data = Base64.getDecoder().decode(input.getBytes("UTF-8"));
            byte[] random = new byte[256];
            byte[] payload = new byte[data.length - 256];

            int x = 0;
            for(int i=0; i<data.length; i++) {
                if(i >= random.length) {
                    payload[x] = data[i];
                    x++;
                } else {
                    random[i] = data[i];
                }
            }

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            byte[] key = new byte[32];
            byte[] iv = new byte[12];
            byte[] output = cipher.doFinal(random);
            x=0;
            for(int i=0; i<output.length; i++) {
                if(i>=32) {
                    iv[x] = output[i];
                    x++;
                } else {
                    key[i] = output[i];
                }
            }
            byte[] result = AES.gcm(payload, key, iv, null, false);

            return new String(result);

        } catch (Exception ex) {

            ex.printStackTrace();

        }

        return "";


    }

    public static String encrypt(String input, String publicKey) {

        return encrypt(input, publicKeyFromStr(publicKey));

    }

    public static String decrypt(String input, String privateKey) {

        return decrypt(input, privateKeyFromStr(privateKey));

    }

}
