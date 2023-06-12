package mancitiss.blockchainserver;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.Sign;

public class EthersUtils {

    public static byte[] signData(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    public static boolean verifySignature(byte[] data, byte[] signature, PublicKey publicKey) throws Exception {
        Signature verifySignature = Signature.getInstance("SHA256withECDSA");
        verifySignature.initVerify(publicKey);
        verifySignature.update(data);
        return verifySignature.verify(signature);
    }
    
    public static Boolean verifyMessage(byte[] message, ECDSASignature signature, BigInteger pub) {
        return EthersUtils.recoverAddress(message, signature, pub);
    }

    public static Boolean recoverAddress(byte[] message, ECDSASignature signature, BigInteger pub) {
        for (int recId = 0; recId < 4; recId++) {
            //System.out.println(recId);
            BigInteger key = Sign.recoverFromSignature(
                    recId,
                    signature,
                    message);
            // if (key != null)
            //     System.out.println(key);
            if (key != null && pub.compareTo(key) == 0) {
                return true;
            }
        }
        return false;
    }
}