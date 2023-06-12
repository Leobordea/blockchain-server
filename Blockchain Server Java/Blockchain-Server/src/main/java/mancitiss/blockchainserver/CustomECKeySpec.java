package mancitiss.blockchainserver;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;

public class CustomECKeySpec {
    BigInteger s, x, y, xg, yg, n, A, B, p;
    int h;
    byte[] seed;

    CustomECKeySpec(KeyPair keyPair) throws NoSuchAlgorithmException, InvalidKeySpecException{
        CustomECKeySpec k = getPrivateKeySpec(keyPair);
        CustomECKeySpec k2 = getPublicKeySpec(keyPair);

        this.s = k.s;
        this.x = k2.x;
        this.y = k2.y;
        this.xg = k.xg;
        this.yg = k.yg;
        this.n = k.n;
        this.h = k.h;
        this.A = k.A;
        this.B = k.B;
        this.seed = k.seed;
        this.p = k.p;
    }

    CustomECKeySpec(ECPublicKeySpec ecPublicKeySpec){
        this.x = ecPublicKeySpec.getW().getAffineX();
        this.y = ecPublicKeySpec.getW().getAffineY();
        this.xg = ecPublicKeySpec.getParams().getGenerator().getAffineX();
        this.yg = ecPublicKeySpec.getParams().getGenerator().getAffineY();
        this.n = ecPublicKeySpec.getParams().getOrder();
        this.h = ecPublicKeySpec.getParams().getCofactor();
        this.A = ecPublicKeySpec.getParams().getCurve().getA();
        this.B = ecPublicKeySpec.getParams().getCurve().getB();
        this.seed = ecPublicKeySpec.getParams().getCurve().getSeed();
        ECFieldFp field = (ECFieldFp) ecPublicKeySpec.getParams().getCurve().getField();
        this.p = field.getP();
    }

    CustomECKeySpec(ECPrivateKeySpec ecPrivateKeySpec){
        this.s = ecPrivateKeySpec.getS();
        this.xg = ecPrivateKeySpec.getParams().getGenerator().getAffineX();
        this.yg = ecPrivateKeySpec.getParams().getGenerator().getAffineY();
        this.n = ecPrivateKeySpec.getParams().getOrder();
        this.h = ecPrivateKeySpec.getParams().getCofactor();
        this.A = ecPrivateKeySpec.getParams().getCurve().getA();
        this.B = ecPrivateKeySpec.getParams().getCurve().getB();
        this.seed = ecPrivateKeySpec.getParams().getCurve().getSeed();
        ECFieldFp field = (ECFieldFp) ecPrivateKeySpec.getParams().getCurve().getField();
        this.p = field.getP();
    }

    ECPublicKeySpec getPublicKeySpec(){
        return new ECPublicKeySpec(new ECPoint(x, y), new ECParameterSpec(new EllipticCurve(new ECFieldFp(p), A, B, seed), new ECPoint(xg, yg), n, h));
    }

    ECPrivateKeySpec getPrivateKeySpec(){
        return new ECPrivateKeySpec(s, new ECParameterSpec(new EllipticCurve(new ECFieldFp(p), A, B, seed), new ECPoint(xg, yg), n, h));
    }

    public static CustomECKeySpec getPrivateKeySpec(KeyPair keyPair) throws NoSuchAlgorithmException, InvalidKeySpecException{
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        ECPrivateKeySpec keyspec = keyFactory.getKeySpec(keyPair.getPrivate(), ECPrivateKeySpec.class);
        return new CustomECKeySpec(keyspec);
    }

    public static CustomECKeySpec getPublicKeySpec(KeyPair keyPair) throws NoSuchAlgorithmException, InvalidKeySpecException{
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        ECPublicKeySpec keyspec = keyFactory.getKeySpec(keyPair.getPublic(), ECPublicKeySpec.class);
        return new CustomECKeySpec(keyspec);
    }
}
