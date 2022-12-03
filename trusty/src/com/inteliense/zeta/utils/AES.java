package com.inteliense.zeta.utils;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

public class AES {

    public static class BASE64 {

        public static String ecb(String input, String key, boolean encrypt) {

            if(encrypt) {

                byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
                byte[] keyBytes = java.util.Base64.getDecoder().decode(key);
                byte[] res = AES.ecb(inputBytes, keyBytes, encrypt);

                if(res != null)
                    return java.util.Base64.getEncoder().encodeToString(res);
                else
                    return "";

            } else {

                byte[] inputBytes = java.util.Base64.getDecoder().decode(input.getBytes(StandardCharsets.UTF_8));
                byte[] keyBytes = java.util.Base64.getDecoder().decode(key);
                byte[] res = AES.ecb(inputBytes, keyBytes, encrypt);

                if(res != null)
                    return new String(res);
                else
                    return "";

            }

        }

        public static String ecb(String input, byte[] key, boolean encrypt) {

            if(encrypt) {

                byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
                byte[] res = AES.ecb(inputBytes, key, encrypt);

                return java.util.Base64.getEncoder().encodeToString(res);

            } else {

                byte[] inputBytes = java.util.Base64.getDecoder().decode(input.getBytes(StandardCharsets.UTF_8));
                byte[] res = AES.ecb(inputBytes, key, encrypt);

                return new String(res);

            }

        }

        public static String cbc(String input, String key, String iv, boolean encrypt) {

            if(encrypt) {

                byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
                byte[] keyBytes = java.util.Base64.getDecoder().decode(key);
                byte[] ivBytes = java.util.Base64.getDecoder().decode(iv);
                byte[] res = AES.cbc(inputBytes, keyBytes, ivBytes, encrypt);

                if(res != null)
                    return java.util.Base64.getEncoder().encodeToString(res);
                else
                    return "";

            } else {

                byte[] inputBytes = java.util.Base64.getDecoder().decode(input.getBytes(StandardCharsets.UTF_8));
                byte[] keyBytes = java.util.Base64.getDecoder().decode(key);
                byte[] ivBytes = java.util.Base64.getDecoder().decode(iv);
                byte[] res = AES.cbc(inputBytes, keyBytes, ivBytes, encrypt);

                if(res != null)
                    return new String(res);
                else
                    return "";

            }

        }

        public static String cbc(String input, byte[] key, byte[] iv, boolean encrypt) {

            if(encrypt) {

                byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
                byte[] res = AES.cbc(inputBytes, key, iv, encrypt);

                if(res != null)
                    return java.util.Base64.getEncoder().encodeToString(res);
                else
                    return "";

            } else {

                byte[] inputBytes = java.util.Base64.getDecoder().decode(input.getBytes(StandardCharsets.UTF_8));
                byte[] res = AES.cbc(inputBytes, key, iv, encrypt);

                if(res != null)
                    return new String(res);
                else
                    return "";

            }

        }

        public static String gcm(String input, String key, String iv, String aad, boolean encrypt) {

            if(encrypt) {

                byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
                byte[] keyBytes = java.util.Base64.getDecoder().decode(key);
                byte[] ivBytes = java.util.Base64.getDecoder().decode(iv);
                byte[] aadBytes = (aad == null) ? null : java.util.Base64.getDecoder().decode(aad);
                byte[] res = AES.gcm(inputBytes, keyBytes, ivBytes, aadBytes, encrypt);

                if(res != null)
                    return java.util.Base64.getEncoder().encodeToString(res);
                else
                    return "";

            } else {

                byte[] inputBytes = java.util.Base64.getDecoder().decode(input.getBytes(StandardCharsets.UTF_8));
                byte[] keyBytes = java.util.Base64.getDecoder().decode(key);
                byte[] ivBytes = java.util.Base64.getDecoder().decode(iv);
                byte[] aadBytes = (aad == null) ? null : java.util.Base64.getDecoder().decode(aad);
                byte[] res = AES.gcm(inputBytes, keyBytes, ivBytes, aadBytes, encrypt);

                if(res != null)
                    return new String(res);
                else
                    return "";

            }

        }

        public static String gcm(String input, byte[] key, byte[] iv, byte[] aad, boolean encrypt) {

            if(encrypt) {

                byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
                byte[] res = AES.gcm(inputBytes, key, iv, aad, encrypt);

                if(res != null)
                    return java.util.Base64.getEncoder().encodeToString(res);
                else
                    return "";

            } else {

                byte[] inputBytes = java.util.Base64.getDecoder().decode(input.getBytes(StandardCharsets.UTF_8));
                byte[] res = AES.gcm(inputBytes, key, iv, aad, encrypt);

                if(res != null)
                    return new String(res);
                else
                    return "";

            }

        }

    }

    public static class HEX {

        public static String ecb(String input, String key, boolean encrypt) {

            if(encrypt) {

                byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
                byte[] keyBytes = EncodingUtils.fromHex(key);
                byte[] res = AES.ecb(inputBytes, keyBytes, encrypt);

                if(res != null)
                    return EncodingUtils.getHex(res);
                else
                    return "";

            } else {

                byte[] inputBytes = EncodingUtils.fromHex(input);
                byte[] keyBytes = EncodingUtils.fromHex(key);
                byte[] res = AES.ecb(inputBytes, keyBytes, encrypt);

                if(res != null)
                    return new String(res);
                else
                    return "";

            }

        }

        public static String ecb(String input, byte[] key, boolean encrypt) {

            if(encrypt) {

                byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
                byte[] res = AES.ecb(inputBytes, key, encrypt);

                return EncodingUtils.getHex(res);

            } else {

                byte[] inputBytes = EncodingUtils.fromHex(input);
                byte[] res = AES.ecb(inputBytes, key, encrypt);

                return new String(res);

            }

        }

        public static String cbc(String input, String key, String iv, boolean encrypt) {

            if(encrypt) {

                byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
                byte[] keyBytes = EncodingUtils.fromHex(key);
                byte[] ivBytes = EncodingUtils.fromHex(iv);
                byte[] res = AES.cbc(inputBytes, keyBytes, ivBytes, encrypt);

                if(res != null)
                    return EncodingUtils.getHex(res);
                else
                    return "";

            } else {

                byte[] inputBytes = EncodingUtils.fromHex(input);
                byte[] keyBytes = EncodingUtils.fromHex(key);
                byte[] ivBytes = EncodingUtils.fromHex(iv);
                byte[] res = AES.cbc(inputBytes, keyBytes, ivBytes, encrypt);

                if(res != null)
                    return new String(res);
                else
                    return "";

            }

        }

        public static String cbc(String input, byte[] key, byte[] iv, boolean encrypt) {

            if(encrypt) {

                byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
                byte[] res = AES.cbc(inputBytes, key, iv, encrypt);

                if(res != null)
                    return EncodingUtils.getHex(res);
                else
                    return "";

            } else {

                byte[] inputBytes = EncodingUtils.fromHex(input);
                byte[] res = AES.cbc(inputBytes, key, iv, encrypt);

                if(res != null)
                    return new String(res);
                else
                    return "";

            }

        }

        public static String gcm(String input, String key, String iv, String aad, boolean encrypt) {

            if(encrypt) {

                byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
                byte[] keyBytes = EncodingUtils.fromHex(key);
                byte[] ivBytes = EncodingUtils.fromHex(iv);
                byte[] aadBytes = (aad == null) ? null : EncodingUtils.fromHex(aad);
                byte[] res = AES.gcm(inputBytes, keyBytes, ivBytes, aadBytes, encrypt);

                if(res != null)
                    return EncodingUtils.getHex(res);
                else
                    return "";

            } else {

                byte[] inputBytes = EncodingUtils.fromHex(input);
                byte[] keyBytes = EncodingUtils.fromHex(key);
                byte[] ivBytes = EncodingUtils.fromHex(iv);
                byte[] aadBytes = (aad == null) ? null : EncodingUtils.fromHex(aad);
                byte[] res = AES.gcm(inputBytes, keyBytes, ivBytes, aadBytes, encrypt);

                if(res != null)
                    return new String(res);
                else
                    return "";

            }

        }

        public static String gcm(String input, byte[] key, byte[] iv, byte[] aad, boolean encrypt) {

            if(encrypt) {

                byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
                byte[] res = AES.gcm(inputBytes, key, iv, aad, encrypt);

                if(res != null)
                    return EncodingUtils.getHex(res);
                else
                    return "";

            } else {

                byte[] inputBytes = EncodingUtils.fromHex(input);
                byte[] res = AES.gcm(inputBytes, key, iv, aad, encrypt);

                if(res != null)
                    return new String(res);
                else
                    return "";

            }

        }

    }

    public static byte[] ecb(byte[] input, byte[] key, boolean encrypt) {

        try {

            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init((encrypt) ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, secretKeySpec);
            return cipher.doFinal(input);

        } catch (Exception ex) {

            ex.printStackTrace();

        }

        return null;

    }

    public static byte[] cbc(byte[] input, byte[] key, byte[] iv, boolean encrypt) {

        try {

            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init((encrypt) ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            return cipher.doFinal(input);

        } catch (Exception ex) {

            ex.printStackTrace();

        }

        return null;

    }

    public static byte[] gcm(byte[] input, byte[] key, byte[] iv, byte[] aad, boolean encrypt) {

        try {

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
            cipher.init((encrypt) ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
            if (aad != null) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(input);

        } catch (Exception ex) {

            ex.printStackTrace();

        }

        return null;

    }

}