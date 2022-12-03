package com.inteliense.zeta.server;

import com.inteliense.zeta.utils.EncodingUtils;
import com.inteliense.zeta.utils.RSA;
import com.inteliense.zeta.utils.SHA;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class ZeroTrustKeyPairs {

    private AsymmetricKey clientPrivate;
    private AsymmetricKey serverPrivate;
    private AsymmetricKey clientPublic;
    private AsymmetricKey serverPublic;

    private String keySetId;

    public ZeroTrustKeyPairs(ClientSession clientSession) {

        KeyPair[] keyPairs = getKeyPairs();
        String apiSecret = clientSession.getClient().getApiSecret();
        clientPublic = new AsymmetricKey(keyPairs[0].getPublic(), apiSecret);
        clientPrivate = new AsymmetricKey(keyPairs[0].getPrivate(), apiSecret);
        serverPublic = new AsymmetricKey(keyPairs[1].getPublic(), apiSecret);
        serverPrivate = new AsymmetricKey(keyPairs[1].getPrivate(), apiSecret);
        String keySetIdHashVal = clientPublic.getPublicKeyId() +
                clientPrivate.getPrivateKeyId() +
                serverPublic.getPublicKeyId() +
                serverPrivate.getPrivateKey();
        keySetId = SHA.getSha1(keySetIdHashVal);
        keyPairs = null;

    }

    public void clear() {

        clientPrivate.clearKeys();
        serverPublic.clearKeys();

    }

    public AsymmetricKey getClientPrivate() {

        return clientPrivate;

    }

    public String getKeySetId() {
        return keySetId;
    }

    public AsymmetricKey getServerPrivate() {

        return serverPrivate;

    }

    public AsymmetricKey getClientPublic() {

        return clientPublic;

    }

    public AsymmetricKey getServerPublic() {

        return serverPublic;

    }

    private KeyPair[] getKeyPairs() {

        KeyPair kp1 = RSA.generateKeyPair();
        KeyPair kp2 = RSA.generateKeyPair();

        return new KeyPair[]{kp1, kp2};

    }

    public class AsymmetricKey {

        private PrivateKey privateKey;
        private PublicKey publicKey;
        private String privateKeyId;
        private String publicKeyId;

        public AsymmetricKey(PrivateKey privateKey, String apiSecret) {

            this.privateKey = privateKey;
            byte[] bites = privateKey.getEncoded();
            String base64 = EncodingUtils.getBase64(bites);
            privateKeyId = SHA.getSha1(SHA.getHmac384(base64, apiSecret));

        }

        public AsymmetricKey(PublicKey publicKey, String apiSecret) {

            this.publicKey = publicKey;
            byte[] bites = publicKey.getEncoded();
            String base64 = EncodingUtils.getBase64(bites);
            publicKeyId = SHA.getSha1(SHA.getHmac384(base64, apiSecret));

        }
        public PrivateKey getPrivateKey() {
            return privateKey;
        }

        public PublicKey getPublicKey() {
            return publicKey;
        }

        public String getPrivateKeyId() {
            return privateKeyId;
        }

        public String getPublicKeyId() {
            return publicKeyId;
        }

        public void clearKeys() {
            this.publicKey = null;
            this.privateKey = null;
            this.privateKeyId = "";
            this.publicKeyId = "";
        }

    }

}
