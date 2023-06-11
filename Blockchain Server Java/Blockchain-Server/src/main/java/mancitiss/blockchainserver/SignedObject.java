package mancitiss.blockchainserver;

import org.web3j.crypto.ECDSASignature;

public class SignedObject {
    public String objectString;
    public ECDSASignature signature;
}
