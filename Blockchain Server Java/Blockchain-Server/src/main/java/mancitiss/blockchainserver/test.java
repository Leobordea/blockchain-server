package mancitiss.blockchainserver;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.sql.Timestamp;

import com.google.gson.Gson;

import javax.net.SocketFactory;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.math.BigInteger;
import java.net.Socket;

public class test {
    private static class MyObject{
        Timestamp time;
        MyObject(Timestamp time){
            this.time = time;
        }
    }    
    public static final String SERVER_ADDRESS = "127.0.0.1";
    public static final int SERVER_PORT = 4001;
    
    public static SocketFactory sf = (SocketFactory)SocketFactory.getDefault();
    public static Socket client;
    public static DataOutputStream dos;
    public static DataInputStream dis;
    public static void main(String[] args) throws Exception { 
        KeyPair keyPair = getKey();

        // // Data to be signed
        // byte[] data = "Hello, world!".getBytes();

        // // Sign the data
        // byte[] signature = EthersUtils.signData(data, keyPair.getPrivate());
        // System.out.println("Signature: " + bytesToHex(signature));

        // // Verify the signature
        // boolean isValid = EthersUtils.verifySignature(data, signature, keyPair.getPublic());
        // System.out.println("Signature verification result: " + isValid);

        // BigInteger bigInt = new BigInteger("1F", 16);
        // System.out.println(bigInt.toString(16));

        try{
            createNewAddress(keyPair);
        }
        catch(Exception e){System.out.println(e);}
        try{
            fetch(keyPair);
        }
        catch(Exception e){System.out.println(e);}
        try{
            addVirus(keyPair);
        }
        catch(Exception e){System.out.println(e);}
        try{
            transfer(keyPair);
        }
        catch(Exception e){System.out.println(e);}

        //

        //
        // Timestamp t = new Timestamp(System.currentTimeMillis());
        // System.out.println(t);
        // System.out.println(t.getTime());
        // System.out.println(t.toString());
        // System.out.println(t.toInstant());
        //
        //MyObject m = new MyObject(t);
        // set time format in nanoseconds for gsonbuilder
        //Gson gson = new GsonBuilder().setDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").create();
        //String json = gson.toJson(m);
        //System.out.println(json);
    }
    
    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02X", b));
        }
        return result.toString();
    }

    public static KeyPair getKey() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        // get key
        String json = "";
        Gson gson = new Gson();
        if (json.equals("")){
            KeyPairGenerator keygen = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
            keygen.initialize(ecSpec);
            KeyPair keyPair = keygen.generateKeyPair();
            //test.createNewAddress(keyPair);
            String keyPairString = gson.toJson(new CustomECKeySpec(keyPair), CustomECKeySpec.class);
            // SharedPreferences.Editor editor = sharedPref.edit();
            // editor.putString(context.getString(R.string.saved_key), keyPairString);
            // editor.apply();
            return keyPair;
        }
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        String saved_key = "";
        CustomECKeySpec customECKeySpec = gson.fromJson(saved_key, CustomECKeySpec.class);
        PrivateKey privateKey = keyFactory.generatePrivate(customECKeySpec.getPrivateKeySpec());
        PublicKey publicKey =  keyFactory.generatePublic(customECKeySpec.getPublicKeySpec());
        KeyPair keyPair = new KeyPair(publicKey, privateKey);
        return keyPair;
    }

    static void createNewAddress(KeyPair keyPair) throws Exception{
        Gson gson = new Gson();
        SignedObject so = new SignedObject();
        
        so.objectString = gson.toJson(CustomECKeySpec.getPublicKeySpec(keyPair), CustomECKeySpec.class);

        // Print the private key.
        System.out.println("private: " + (new BigInteger(keyPair.getPrivate().getEncoded())).toString(16));
        // Print the public key.
        System.out.println("pub: " + (new BigInteger(keyPair.getPublic().getEncoded())).toString(16));
        byte[] signature = EthersUtils.signData(so.objectString.getBytes(StandardCharsets.US_ASCII), keyPair.getPrivate());

        so.signature = signature;

        String objectString = gson.toJson(so, SignedObject.class);

        System.out.println(objectString);        

        Socket client = (Socket) sf.createSocket(SERVER_ADDRESS, SERVER_PORT);
        System.out.println("HASH: " + client.hashCode());
        dis = new DataInputStream(client.getInputStream());
        dos = new DataOutputStream(client.getOutputStream());
        dos.write(Tools.combine("0200".getBytes(StandardCharsets.UTF_16LE), Tools.data_with_ASCII_byte(objectString).getBytes(StandardCharsets.US_ASCII)));
        String code = Tools.receive_unicode(dis, 8);
        System.out.println(code);
        dis.close();
        dos.close();
        client.close();
        System.out.println("=====================");
    }

    static void fetch(KeyPair keyPair) throws Exception{
        Gson gson = new Gson();
        SignedObject so = new SignedObject();
        so.objectString = gson.toJson(CustomECKeySpec.getPublicKeySpec(keyPair), CustomECKeySpec.class);

        byte[] signature = EthersUtils.signData(so.objectString.getBytes(StandardCharsets.US_ASCII), keyPair.getPrivate());
        so.signature = signature;

        String objectString = gson.toJson(so, SignedObject.class);
        System.out.println(objectString);

        Socket client = (Socket) sf.createSocket(SERVER_ADDRESS, SERVER_PORT);
        dis = new DataInputStream(client.getInputStream());
        dos = new DataOutputStream(client.getOutputStream());

        dos.write(Tools.combine("0001".getBytes(StandardCharsets.UTF_16LE), Tools.data_with_ASCII_byte(objectString).getBytes(StandardCharsets.US_ASCII)));
        String code = Tools.receive_unicode(dis, 8);
        System.out.println(code);
        String result = Tools.receive_ASCII_Automatically(dis);
        System.out.println(result);
        dis.close();
        dos.close();
        client.close();
        System.out.println("=====================");
    }

    static void addVirus(KeyPair keyPair) throws Exception{
        Gson gson = new Gson();
        SignedObject so = new SignedObject();
        Virus virus = new Virus();
        virus.publicKey = CustomECKeySpec.getPublicKeySpec(keyPair);
        virus.virusSignature = "abcde";
        so.objectString = gson.toJson(virus, Virus.class);

        byte[] signature = EthersUtils.signData(so.objectString.getBytes(StandardCharsets.US_ASCII), keyPair.getPrivate());
        so.signature = signature;

        String objectString = gson.toJson(so, SignedObject.class);
        System.out.println(objectString);

        Socket client = (Socket) sf.createSocket(SERVER_ADDRESS, SERVER_PORT);
        dis = new DataInputStream(client.getInputStream());
        dos = new DataOutputStream(client.getOutputStream());

        dos.write(Tools.combine("0002".getBytes(StandardCharsets.UTF_16LE), Tools.data_with_ASCII_byte(objectString).getBytes(StandardCharsets.US_ASCII)));
        String code = Tools.receive_unicode(dis, 8);
        System.out.println(code);
        // String result = Tools.receive_ASCII_Automatically(dis);
        // System.out.println(result);
        dis.close();
        dos.close();
        client.close();
        System.out.println("=====================");
    }

    static void transfer(KeyPair keyPair) throws Exception{
        Gson gson = new Gson();
        SignedObject so = new SignedObject();
        Transfer transfer = new Transfer();

        transfer.senderPublicKey = CustomECKeySpec.getPublicKeySpec(keyPair);
        transfer.receiverPublicBigInt = BigInteger.valueOf(10);

        int i = 200;
        transfer.value = i;
        so.objectString = gson.toJson(transfer, Transfer.class);

        byte[] signature = EthersUtils.signData(so.objectString.getBytes(StandardCharsets.US_ASCII), keyPair.getPrivate());
        so.signature = signature;

        String objectString = gson.toJson(so, SignedObject.class);
        System.out.println(objectString);

        Socket client = (Socket) sf.createSocket(SERVER_ADDRESS, SERVER_PORT);
        System.out.println("HASH: " + client.hashCode());
        dis = new DataInputStream(client.getInputStream());
        dos = new DataOutputStream(client.getOutputStream());

        dos.write(Tools.combine("0003".getBytes(StandardCharsets.UTF_16LE), Tools.data_with_ASCII_byte(objectString).getBytes(StandardCharsets.US_ASCII)));
        String code = Tools.receive_unicode(dis, 8);
        System.out.println(code);
        dis.close();
        dos.close();
        client.close();
        System.out.println("=====================");
    }
}
