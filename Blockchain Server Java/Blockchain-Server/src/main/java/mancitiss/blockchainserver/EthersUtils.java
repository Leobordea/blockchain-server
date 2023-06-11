package mancitiss.blockchainserver;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

public class EthersUtils {
    
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