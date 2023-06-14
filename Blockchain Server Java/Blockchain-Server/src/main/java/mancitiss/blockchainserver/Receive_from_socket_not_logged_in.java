package mancitiss.blockchainserver;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;

import com.google.gson.Gson;

import java.net.Socket;

public class Receive_from_socket_not_logged_in implements Runnable {
    Socket client;

    public Receive_from_socket_not_logged_in(Socket client) {
        this.client = client;
    }

    @Override
    public void run() {
        try (
                DataInputStream DIS = new DataInputStream(client.getInputStream());
                DataOutputStream DOS = new DataOutputStream(client.getOutputStream())) {
            // create streams from client

            String data = Tools.receive_unicode(DIS, 8);
            System.out.println(data);
            if (data != null && !data.isEmpty()) {
                String instruction = data;
                if (instruction.equals("0200")) { // create address
                    //
                    System.out.println("login");
                    String serialized = Tools.receive_ASCII_Automatically(DIS);
                    //System.out.println(serialized);
                    Gson gson = new Gson();
                    SignedObject obj = gson.fromJson(serialized, SignedObject.class);
                    CustomECKeySpec spec = gson.fromJson(obj.objectString, CustomECKeySpec.class);

                    KeyFactory kf = KeyFactory.getInstance("EC");
                    PublicKey publicKey = kf.generatePublic(spec.getPublicKeySpec());

                    byte[] digest = obj.objectString.getBytes(StandardCharsets.US_ASCII);

                    if (!EthersUtils.verifySignature(digest, obj.signature, publicKey))
                        throw new Exception("Signature doesn't match");

                    String id = (new BigInteger(publicKey.getEncoded())).toString(16);
                    System.out.println(id);
                    int result = Program.addKey(id);
                    if (result == 0)
                        DOS.write("0200".getBytes(StandardCharsets.UTF_16LE));
                    else
                        DOS.write("-200".getBytes(StandardCharsets.UTF_16LE));
                    DOS.close();
                    DIS.close();
                    client.close();
                }
                else if (instruction.equals("0001")){ // fetch coin
                    System.out.println("fetch");
                    String serialized = Tools.receive_ASCII_Automatically(DIS);
                    //System.out.println(serialized);
                    Gson gson = new Gson();
                    SignedObject obj = gson.fromJson(serialized, SignedObject.class);
                    CustomECKeySpec spec = gson.fromJson(obj.objectString, CustomECKeySpec.class);

                    KeyFactory kf = KeyFactory.getInstance("EC");
                    PublicKey publicKey = kf.generatePublic(spec.getPublicKeySpec());
                    
                    byte[] digest = obj.objectString.getBytes(StandardCharsets.US_ASCII);

                    if (!EthersUtils.verifySignature(digest, obj.signature, publicKey))
                        throw new Exception("Signature doesn't match");

                    String id = (new BigInteger(publicKey.getEncoded())).toString(16);
                    System.out.println(id);
                    int result = Program.query(id);
                    DOS.write(Tools.combine(
                        "0001".getBytes(StandardCharsets.UTF_16LE), 
                        Tools.data_with_ASCII_byte(Integer.toString(result)).getBytes(StandardCharsets.US_ASCII)
                    ));
                    DOS.close();
                    DIS.close();
                    client.close();
                }
                else if (instruction.equals("0002")){ // add virus
                    System.out.println("new virus");
                    String serialized = Tools.receive_ASCII_Automatically(DIS);
                    //System.out.println(serialized);
                    Gson gson = new Gson();
                    SignedObject obj = gson.fromJson(serialized, SignedObject.class);
                    Virus virus = gson.fromJson(obj.objectString, Virus.class);

                    KeyFactory kf = KeyFactory.getInstance("EC");
                    PublicKey publicKey = kf.generatePublic(virus.publicKey.getPublicKeySpec());

                    byte[] digest = obj.objectString.getBytes(StandardCharsets.US_ASCII);

                    if (!EthersUtils.verifySignature(digest, obj.signature, publicKey))
                        throw new Exception("Signature doesn't match");

                    if (!Program.verify(virus)){
                        DOS.write(Tools.combine(
                        "0002".getBytes(StandardCharsets.UTF_16LE), 
                        Tools.data_with_ASCII_byte(Integer.toString(-1)).getBytes(StandardCharsets.US_ASCII)
                        ));
                        DOS.close();
                        DIS.close();
                        client.close();
                        return;
                    }
                    String id = (new BigInteger(publicKey.getEncoded())).toString(16);
                    System.out.println(id);
                    int result = Program.addVirus(id, virus);
                    DOS.write(Tools.combine(
                        "0002".getBytes(StandardCharsets.UTF_16LE), 
                        Tools.data_with_ASCII_byte(Integer.toString(result)).getBytes(StandardCharsets.US_ASCII)
                    ));
                    DOS.close();
                    DIS.close();
                    client.close();
                }
                else if (instruction.equals("0003")){
                    System.out.println("transfer");
                    String serialized = Tools.receive_ASCII_Automatically(DIS);

                    Gson gson = new Gson();
                    SignedObject obj = gson.fromJson(serialized, SignedObject.class);
                    Transfer transfer = gson.fromJson(obj.objectString, Transfer.class);

                    KeyFactory kf = KeyFactory.getInstance("EC");
                    PublicKey publicKey = kf.generatePublic(transfer.senderPublicKey.getPublicKeySpec());

                    byte[] digest = obj.objectString.getBytes(StandardCharsets.US_ASCII);
                    
                    // if sender public key can be used to verify this message is from the private key that sign this message
                    // then that mean sender public key is authorized
                    // otherwise this verify will fail if someone try to make someone else send money without their permission.
                    if (!EthersUtils.verifySignature(digest, obj.signature, publicKey)) 
                        throw new Exception("Signature doesn't match");
                    String id = (new BigInteger(publicKey.getEncoded())).toString(16);
                    System.out.println(id);                 
                    System.out.println(transfer.receiverPublicBigInt.toString(16));
                    System.out.println(transfer.value);
                    int result = Program.transfer(id, transfer);
                    System.out.println(result);
                    DOS.write(Tools.combine(
                        "0003".getBytes(StandardCharsets.UTF_16LE), 
                        Tools.data_with_ASCII_byte(Integer.toString(result)).getBytes(StandardCharsets.US_ASCII)
                    ));
                    DOS.close();
                    DIS.close();
                    client.close();
                }
            }
        } catch (Exception e) {
            if (!e.getMessage().contains("terminated the handshake"))
                e.printStackTrace();
            // close all possible resouces with try catch
            try {
                client.close();
            } catch (Exception e1) {
            }
            System.out.println("All resources related to exception closed");
        } finally {
            System.out.flush();
        }
    }
}
