package mancitiss.blockchainserver;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.sql.Timestamp;

import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Keys;

import com.google.gson.Gson;

import javax.net.SocketFactory;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;

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
    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, UnknownHostException, IOException { 

        // Create a new ECKeyPair object.
        ECKeyPair ecKeyPair = Keys.createEcKeyPair();

        BigInteger b = ecKeyPair.getPrivateKey();
        Gson gson = new Gson();
        String bs = gson.toJson(b, BigInteger.class);
        System.out.println(bs);
        System.out.println(b.toString());
        BigInteger b2 = gson.fromJson(bs, BigInteger.class);
        System.out.println(b2.toString());
        System.out.println(b.equals(b2));

        // try{
        //     createNewAddress(ecKeyPair);
        // }
        // catch(Exception e){System.out.println(e);}
        // try{
        //     fetch(ecKeyPair);
        // }
        // catch(Exception e){System.out.println(e);}
        // try{
        //     addVirus(ecKeyPair);
        // }
        // catch(Exception e){System.out.println(e);}
        // try{
        //     transfer(ecKeyPair);
        // }
        // catch(Exception e){System.out.println(e);}
        

        //

        // System.out.println(signature.r);
        // System.out.println(signature.s);

        // Boolean match = EthersUtils.verifyMessage(digest, signature, ecKeyPair.getPublicKey());
        // System.out.println(match);

        // String text = "alo";
        // ECDSASignature sign = ecKeyPair.sign(text.getBytes(StandardCharsets.US_ASCII));
        // System.out.println(EthersUtils.verifyMessage(text.getBytes(StandardCharsets.US_ASCII), sign, ecKeyPair.getPublicKey()));

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

    static void createNewAddress(ECKeyPair ecKeyPair) throws UnknownHostException, IOException, NoSuchAlgorithmException{
        Socket client = (Socket) sf.createSocket(SERVER_ADDRESS, SERVER_PORT);
        System.out.println("HASH: " + client.hashCode());
        dis = new DataInputStream(client.getInputStream());
        dos = new DataOutputStream(client.getOutputStream());

        // Print the public key.
        System.out.println(ecKeyPair.getPublicKey());

        Gson gson = new Gson();
        SignedObject so = new SignedObject();
        so.objectString = gson.toJson(ecKeyPair.getPublicKey(), BigInteger.class);

        // Print the private key.
        System.out.println(ecKeyPair.getPrivateKey());

        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digest = md.digest(so.objectString.getBytes(StandardCharsets.US_ASCII));
        ECDSASignature signature = ecKeyPair.sign(digest);

        so.signature = signature;

        String objectString = gson.toJson(so, SignedObject.class);

        System.out.println(objectString);

        dos.write(Tools.combine("0200".getBytes(StandardCharsets.UTF_16LE), Tools.data_with_ASCII_byte(objectString).getBytes(StandardCharsets.US_ASCII)));
        String code = Tools.receive_unicode(dis, 8);
        System.out.println(code);
        dis.close();
        dos.close();
        client.close();
        System.out.println("=====================");
    }

    static void fetch(ECKeyPair ecKeyPair) throws UnknownHostException, IOException, NoSuchAlgorithmException{
        Socket client = (Socket) sf.createSocket(SERVER_ADDRESS, SERVER_PORT);
        System.out.println("HASH: " + client.hashCode());
        dis = new DataInputStream(client.getInputStream());
        dos = new DataOutputStream(client.getOutputStream());

        // Print the public key.
        System.out.println(ecKeyPair.getPublicKey());

        Gson gson = new Gson();
        SignedObject so = new SignedObject();
        so.objectString = gson.toJson(ecKeyPair.getPublicKey(), BigInteger.class);

        // Print the private key.
        System.out.println(ecKeyPair.getPrivateKey());

        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digest = md.digest(so.objectString.getBytes(StandardCharsets.US_ASCII));
        ECDSASignature signature = ecKeyPair.sign(digest);

        so.signature = signature;

        String objectString = gson.toJson(so, SignedObject.class);

        System.out.println(objectString);

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

    static void addVirus(ECKeyPair ecKeyPair) throws UnknownHostException, IOException, NoSuchAlgorithmException{
        Socket client = (Socket) sf.createSocket(SERVER_ADDRESS, SERVER_PORT);
        System.out.println("HASH: " + client.hashCode());
        dis = new DataInputStream(client.getInputStream());
        dos = new DataOutputStream(client.getOutputStream());

        // Print the public key.
        System.out.println(ecKeyPair.getPublicKey());

        Gson gson = new Gson();
        SignedObject so = new SignedObject();
        Virus virus = new Virus();
        virus.publicKey = ecKeyPair.getPublicKey();
        virus.virusSignature = "abcde";
        so.objectString = gson.toJson(virus, Virus.class);

        // Print the private key.
        System.out.println(ecKeyPair.getPrivateKey());

        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digest = md.digest(so.objectString.getBytes(StandardCharsets.US_ASCII));
        ECDSASignature signature = ecKeyPair.sign(digest);

        so.signature = signature;

        String objectString = gson.toJson(so, SignedObject.class);

        System.out.println(objectString);

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

    static void transfer(ECKeyPair ecKeyPair) throws UnknownHostException, IOException, NoSuchAlgorithmException{
        Socket client = (Socket) sf.createSocket(SERVER_ADDRESS, SERVER_PORT);
        System.out.println("HASH: " + client.hashCode());
        dis = new DataInputStream(client.getInputStream());
        dos = new DataOutputStream(client.getOutputStream());

        // Print the public key.
        System.out.println(ecKeyPair.getPublicKey());

        Gson gson = new Gson();
        SignedObject so = new SignedObject();
        Transfer transfer = new Transfer();
        transfer.senderPublicKey = ecKeyPair.getPublicKey();
        transfer.receiverPublicKey = BigInteger.valueOf(0);
        int i = 0;
        transfer.value = i;
        so.objectString = gson.toJson(transfer, Transfer.class);

        // Print the private key.
        System.out.println(ecKeyPair.getPrivateKey());

        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digest = md.digest(so.objectString.getBytes(StandardCharsets.US_ASCII));
        ECDSASignature signature = ecKeyPair.sign(digest);

        so.signature = signature;

        String objectString = gson.toJson(so, SignedObject.class);

        System.out.println(objectString);

        dos.write(Tools.combine("0003".getBytes(StandardCharsets.UTF_16LE), Tools.data_with_ASCII_byte(objectString).getBytes(StandardCharsets.US_ASCII)));
        String code = Tools.receive_unicode(dis, 8);
        System.out.println(code);
        // String result = Tools.receive_ASCII_Automatically(dis);
        // System.out.println(result);
        dis.close();
        dos.close();
        client.close();
        System.out.println("=====================");
    }
}
