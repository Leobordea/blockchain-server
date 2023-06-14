package mancitiss.blockchainserver;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;

import static java.lang.System.out;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.TimeZone;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.net.ServerSocket;
import javax.net.ServerSocketFactory;

import org.springframework.core.convert.ConversionService;

import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import ch.qos.logback.core.pattern.Converter;

/**
 *
 * @author Mancitiss
 */
public class Program {

    /**
     * @param args the command line arguments
     */
    static ExecutorService executor = Executors.newCachedThreadPool();
    static Calendar tzCal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));

    static Connection sql;
    static String cnurl;

    // object that can random long number
    static java.util.SplittableRandom rand = new java.util.SplittableRandom();

    public static void main(String[] args) {
        try {
            try{
                //System.out.println(query("a"));
                ExecuteServer();
            } catch (Exception e) {
                e.printStackTrace();
            }
        } catch (Exception e) {
            out.println("Error: " + e.toString());
        }
    }

    private static void ExecuteServer() throws IOException {
        ServerSocketFactory ssf = (ServerSocketFactory) ServerSocketFactory.getDefault();
        try (ServerSocket ss = (ServerSocket) ssf.createServerSocket(4001)) {
            // translate below line of code from C#
            // Console.WriteLine("Server at: {0}", IPAddress.Any);
            out.println("Server at: " + ss.getInetAddress());
            try {
                while (true) {
                    Socket client = (Socket) ss.accept();
                    System.out.println("Client connected: " + client.getInetAddress());
                    try {
                        executor.execute(new Receive_from_socket_not_logged_in(client));
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    client = null;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static int query(String id) throws IOException {
        Boolean b = id.matches(Constants.ID_REGEX);
        if (!b) return -1;
        String peer = get_peer(Constants.PEER_REGEX);
        String[] arguments = new String[]{"kubectl" ,"exec", "-it", peer,  "--" ,"/bin/bash" ,"-c", "peer chaincode invoke -o blockchain-orderer:31010 -C channel1 -n cc -c \'{\"Args\":[\"query\",\"" + id + "\"]}\' "};
        
        Process proc = new ProcessBuilder(arguments).start();

        boolean success = false;
        try {
            success = proc.waitFor(20, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            e.printStackTrace();
            return -1;
        }       
        if (!success) return -1;
        System.out.println("Success");
        String[] arguments2 = new String[]{"kubectl" ,"exec", "-it", peer,  "--" ,"/bin/bash" ,"-c", "peer chaincode query -C channel1 -n cc -c \'{\"Args\":[\"query\",\"" + id + "\"]}\' "};

        Process proc2 = new ProcessBuilder(arguments2).start();
        //try{Thread.sleep(6000);} catch(Exception ignored){}
        try (InputStream inputStream = proc2.getInputStream();
                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream))) {
                    String line = bufferedReader.readLine();
                    System.out.println("Reading line");
                    System.out.println(line);
                    if (line != null && line.length() > 0) return Integer.parseInt(line);
                    return -1;
        } catch (Exception e) {
            System.out.println(e);
            return -1;
        }
    }

    static int addKey(String id) throws IOException {
        Boolean b = id.matches(Constants.ID_REGEX);
        if (!b) return -1;
        String peer = get_peer(Constants.PEER_REGEX);
        String[] arguments = new String[]{"kubectl" ,"exec", "-it", peer,  "--" ,"/bin/bash" ,"-c", "peer chaincode invoke -o blockchain-orderer:31010 -C channel1 -n cc -c \'{\"Args\":[\"add\",\"" + id + "\"]}\' "};
        
        Process proc = new ProcessBuilder(arguments).start();
        
        boolean success = false;
        try {
            success = proc.waitFor(20, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            e.printStackTrace();
            return -1;
        }       
        if (!success) return -1;

        String[] arguments2 = new String[]{"kubectl" ,"exec", "-it", peer,  "--" ,"/bin/bash" ,"-c", "peer chaincode query -C channel1 -n cc -c \'{\"Args\":[\"add\",\"" + id + "\"]}\' "};
        
        Process proc2 = new ProcessBuilder(arguments2).start();
        //proc2.waitFor();
        try (InputStream inputStream = proc2.getInputStream();
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream))) {
                String line = bufferedReader.readLine();
                System.out.println("Reading line");
                System.out.println(line);
                if (line != null && line.length() > 0) return 0;
                return -1;
        } catch (Exception e) {
            System.out.println(e);
            return -1;
        }

        // } catch (Exception e) {
        //     System.out.println(e);
        //     return -1;
        // }
    }

    static Boolean verify(Virus virus){ //pseudo code to fake virus verification
        SecureRandom rand = new SecureRandom();
        int rand_int = rand.nextInt(10000);
        if (rand_int < 1907) return true;  // chance is 19.07% of accepting it as a valid virus
        return false;
    }

    static int addVirus(String id, Virus virus) throws IOException {
        Boolean b = id.matches(Constants.ID_REGEX);
        if (!b) return -1;
        String peer = get_peer(Constants.PEER_REGEX);
        String[] arguments = new String[]{"kubectl" ,"exec", "-it", peer,  "--" ,"/bin/bash" ,"-c", "peer chaincode invoke -o blockchain-orderer:31010 -C channel1 -n cc -c \'{\"Args\":[\"addVirus\",\"" + id + "\", \"" + virus.virusSignature + "\"]}\' "};
        
        Process proc = new ProcessBuilder(arguments).start();

        boolean success = false;
        try {
            success = proc.waitFor(20, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            e.printStackTrace();
            return -1;
        }       
        if (!success) return -1;

        String[] arguments2 = new String[]{"kubectl" ,"exec", "-it", peer,  "--" ,"/bin/bash" ,"-c", "peer chaincode query -C channel1 -n cc -c \'{\"Args\":[\"addVirus\",\"" + id + "\", \"" + virus.virusSignature + "\"]}\' "};
        
        Process proc2 = new ProcessBuilder(arguments2).start();


        try (InputStream inputStream = proc2.getInputStream();
                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream))) {
                    String line = bufferedReader.readLine();
                    if (line != null && line.length() > 0) return 0;
                    return -1;

        } catch (Exception e) {
            System.out.println(e);
            return -1;
        }
    }

    static int transfer(String sender, Transfer transfer) throws IOException {
        String receiver = transfer.receiverPublicBigInt.toString(16);
        long value = transfer.value;
        Boolean b = sender.matches(Constants.ID_REGEX);
        if (!b) return -1;
        b = receiver.matches(Constants.ID_REGEX);
        if (!b) return -1;
        String peer = get_peer(Constants.PEER_REGEX);
        String[] arguments = new String[]{"kubectl" ,"exec", "-it", peer,  "--" ,"/bin/bash" ,"-c", "peer chaincode invoke -o blockchain-orderer:31010 -C channel1 -n cc -c \'{\"Args\":[\"invoke\",\"" + sender + "\", \"" + receiver + "\", \"" + value + "\"]}\' "};
        
        Process proc = new ProcessBuilder(arguments).start();
        
        boolean success = false;
        try {
            success = proc.waitFor(20, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            e.printStackTrace();
            return -1;
        }       
        if (!success) return -1;

        String[] arguments2 = new String[]{"kubectl" ,"exec", "-it", peer,  "--" ,"/bin/bash" ,"-c", "peer chaincode query -C channel1 -n cc -c \'{\"Args\":[\"invoke\",\"" + sender + "\", \"" + receiver + "\", \"" + value + "\"]}\' "};
        
        Process proc2 = new ProcessBuilder(arguments2).start();
        try (InputStream inputStream = proc2.getInputStream();
                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream))) {
                    String line = bufferedReader.readLine();
                    if (line != null && line.length() > 0) return 0;
                    return -1;

        } catch (Exception e) {
            System.out.println(e);
            return -1;
        }
    }

    static String get_peer(String reg) throws IOException{
        Process proc = new ProcessBuilder(Constants.GET_PODS.split(" ")).start();
        ArrayList<String> list = new ArrayList<String>();
        try (InputStream inputStream = proc.getInputStream();
                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream))) {

            String line;
            while ((line = bufferedReader.readLine()) != null) {
                if (line.isBlank() || !line.matches(reg)) continue;
                list.add(line.split(" ")[0]);
            }

        } catch (IOException e) {
            System.out.println(e);
        }
        int rd = rand.nextInt(list.size());
        return list.get(rd);
    }
}
