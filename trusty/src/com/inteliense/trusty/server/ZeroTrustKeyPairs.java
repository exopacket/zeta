package com.inteliense.trusty.server;

import com.inteliense.trusty.utils.RSA;
import com.inteliense.trusty.utils.Random;
import com.inteliense.trusty.utils.SHA;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class ZeroTrustKeyPairs {

    private AsymmetricKey clientPrivate;
    private AsymmetricKey serverPrivate;
    private AsymmetricKey clientPublic;
    private AsymmetricKey serverPublic;

    private byte[] random;

    private String randomHash;

    public ZeroTrustKeyPairs(RemoteClient client) {

        //packet
        //random bytes, server public, client private

        KeyPair[] keyPairs = getKeyPairs();
        clientPublic = new AsymmetricKey(keyPairs[0].getPublic());
        clientPrivate = new AsymmetricKey(keyPairs[0].getPrivate());
        serverPublic = new AsymmetricKey(keyPairs[1].getPublic());
        serverPrivate = new AsymmetricKey(keyPairs[1].getPrivate());
        keyPairs = null;
        random = Random.secure(128);
        randomHash = SHA.get384(random);

    }

    public void clear() {

        clientPrivate.clearKeys();
        serverPublic.clearKeys();

    }

    public PrivateKey getClientPrivate() {

        return clientPrivate.getPrivateKey();

    }

    public PrivateKey getServerPrivate() {

        return serverPrivate.getPrivateKey();

    }

    public PublicKey getClientPublic() {

        return clientPublic.getPublicKey();

    }

    public PublicKey getServerPublic() {

        return serverPublic.getPublicKey();

    }

    private KeyPair[] getKeyPairs() {

        KeyPair kp1 = RSA.generateKeyPair();
        KeyPair kp2 = RSA.generateKeyPair();

        return new KeyPair[]{kp1, kp2};

    }

    private class AsymmetricKey {

        private PrivateKey privateKey;
        private PublicKey publicKey;

        public AsymmetricKey(PrivateKey privateKey) {
            this.privateKey = privateKey;
        }

        public AsymmetricKey(PublicKey publicKey) {
            this.publicKey = publicKey;
        }
        public PrivateKey getPrivateKey() {
            return privateKey;
        }

        public PublicKey getPublicKey() {
            return publicKey;
        }

        public void clearKeys() {
            this.publicKey = null;
            this.privateKey = null;
        }

    }

}
