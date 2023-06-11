package com.mycompany.afriendjava;

import java.awt.Color;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicReference;

import javax.imageio.ImageIO;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.swing.SwingUtilities;

public class AFriendClient{
    public static final String SERVER_ADDRESS = "mancitiss.duckdns.org";
    public static final int SERVER_PORT = 11111;

    private static String instruction;

    private static HashMap<String, List<MessageObject>> first = new HashMap<String, List<MessageObject>>();
    public static HashMap<String, AFile> files = new HashMap<String, AFile>();

    public static String tempName = null;
    public static String imgString = null;
    public static byte publicState = 0;

    public static SSLSocketFactory ssf = (SSLSocketFactory)SSLSocketFactory.getDefault();
    public static SSLSocket client;
    public static DataOutputStream dos;
    public static DataInputStream dis;
    public static Account user;

    public static boolean loginResult = true;

    private static AtomicReference<Integer> workerAdded = new AtomicReference<Integer>(0);
    private static AtomicReference<Integer> sendFileWorker = new AtomicReference<Integer>(0);
    private static AtomicReference<Integer> writeFileAdded = new AtomicReference<Integer>(0);
    public static ConcurrentLinkedQueue<byte[]> commands = new ConcurrentLinkedQueue<byte[]>();
    public static ConcurrentLinkedQueue<Slot> availableSlots = new ConcurrentLinkedQueue<Slot>();
    public static ConcurrentLinkedQueue<WriteCommand> writeCommands = new ConcurrentLinkedQueue<WriteCommand>();
    public static ConcurrentHashMap<String, Boolean> filesOnCancel = new ConcurrentHashMap<String, Boolean>();

    private static void addWriteThread(){
        if (writeFileAdded.getAndSet(1) == 0){
            try{
                Thread thread = new Thread(new Runnable(){
                    @Override
                    public void run() {
                        try{
                            while(!writeCommands.isEmpty()){
                                WriteCommand wc = writeCommands.poll();
                                try{
                                    if (files.get(wc.file).fos != null){
                                        //if (files.get(wc.file).fos.getChannel().isOpen()){
                                            files.get(wc.file).fos.getChannel().position(wc.offset);
                                            files.get(wc.file).fos.write(wc.databyte, 0, wc.received_byte);
                                            files.get(wc.file).size -= wc.received_byte;
                                            if (files.get(wc.file).size <= 0){
                                                files.get(wc.file).fos.flush();
                                                files.get(wc.file).fos.close();
                                                files.get(wc.file).fos = null;
                                                files.remove(wc.file);
                                                System.out.println("Done");
                                            }
                                            System.out.println("writing end");
                                        //}
                                    }
                                    else {
                                        files.get(wc.file).fos = new FileOutputStream(files.get(wc.file).name);
                                        files.get(wc.file).fos.getChannel().position(wc.offset);
                                        files.get(wc.file).fos.write(wc.databyte, 0, wc.received_byte);
                                        files.get(wc.file).size -= wc.received_byte;
                                        if (files.get(wc.file).size == 0){
                                            files.get(wc.file).fos.close();
                                            files.get(wc.file).fos = null;
                                            files.remove(wc.file);
                                        }
                                        System.out.println("File " + wc.file + " written");
                                    }
                                }
                                catch (Exception e){
                                    if (e.toString().contains("being used by another process")){
                                        System.out.println("try again! Thread ID: " + Thread.currentThread().getId() + ", offset: " + wc.offset);
                                        writeCommands.add(wc);
                                    }
                                    else {
                                        System.out.println("Error: " + e.toString());
                                        files.get(wc.file).fos.close();
                                        files.remove(wc.file);
                                    }
                                }
                            }
                        }
                        catch (Exception e){
                            e.printStackTrace();
                        }
                        finally{
                            writeFileAdded.set(0);
                            System.out.println("Write stopped");
                        }
                    }
                });
                thread.start();
            }
            catch (Exception e){
                e.printStackTrace();
                writeFileAdded.set(0);
            }
        }
        else{
            System.out.println("Running");
        }
    }
 
    public static void queueSlot(String id, long num, String file, long length){
        availableSlots.add(new Slot(id, num, file, length));
        addSendFileThread();
    }
 
    public static void addSendFileThread(){
        if (0 == sendFileWorker.getAndSet(1)){
            try{
                new Thread(new Runnable(){
                    @Override
                    public void run() {
                        System.out.println("Start sending files");
                        try{
                            while(!availableSlots.isEmpty()){
                                Slot s = availableSlots.poll();
                                if (s == null) throw new Exception("Slot is null");
                                boolean fileFound = false;
                                while(!fileFound){
                                    String file = Program.mainform.panelChats.get(s.id).filesToSend.poll();
                                    if (file == null) throw new Exception("File is null");
                                    // check if file path exist and is a file
                                    File f = new File(file);
                                    if (f.exists() && f.isFile()){
                                        // get file name from path
                                        String fileName = file.substring(file.lastIndexOf(File.separator) + 1);
                                        // get file size
                                        long fileSize = f.length();
                                        if (fileName.equals(s.name) && fileSize == s.length){
                                            // send file
                                            System.out.println("Start sending file" + fileName);

                                            fileFound = true;
                                            try{
                                                try(FileInputStream fis = new FileInputStream(f)){
                                                    long offset = 0;
                                                    byte[] buffer = new byte[32768];
                                                    while (offset < fileSize){
                                                        if (filesOnCancel.containsKey(user.id + "_" + s.id + "_" + s.num) ){
                                                            filesOnCancel.remove(user.id + "_" + s.id + "_" + s.num);
                                                            break;
                                                        }
                                                        if (fileSize - offset > buffer.length){
                                                            int first_byte_expected = buffer.length;
                                                            int byte_expected = first_byte_expected;
                                                            int total_byte_received = 0;
                                                            int byte_received;
                                                            do{
                                                                byte_received = fis.read(buffer, total_byte_received, byte_expected);
                                                                if (byte_received > 0){
                                                                    total_byte_received += byte_received;
                                                                    byte_expected -= byte_received;
                                                                }
                                                                else break;
                                                            } while(byte_expected > 0 && byte_received > 0);
                                                            if (total_byte_received == first_byte_expected){
                                                                while (commands.size() > 10) Thread.sleep(25);
                                                                queueCommand(Tools.combine(
                                                                    "1904".getBytes(StandardCharsets.UTF_16LE), 
                                                                    s.id.getBytes(StandardCharsets.UTF_16LE),
                                                                    Tools.data_with_ASCII_byte(Long.toString(s.num)).getBytes(StandardCharsets.US_ASCII),
                                                                    Tools.data_with_ASCII_byte(Long.toString(offset)).getBytes(StandardCharsets.US_ASCII),
                                                                    Tools.data_with_ASCII_byte(Long.toString(byte_received)).getBytes(StandardCharsets.US_ASCII),
                                                                    buffer
                                                                ));
                                                            }
                                                            offset += total_byte_received;
                                                            try{
                                                                // this method is synchronized, its parameters must be volatile
                                                                Program.mainform.panelChats.get(s.id).messages.get(s.num).changeTextUpload((byte)(100 * offset/ fileSize));
                                                            }
                                                            catch (Exception ex){
                                                                ex.printStackTrace();
                                                            }
                                                        }
                                                        else
                                                        {
                                                            int first_byte_expected = (int) (fileSize - offset);
                                                            int byte_expectex = first_byte_expected;
                                                            byte[] final_buffer = new byte[first_byte_expected];
                                                            int total_byte_received = 0;
                                                            int received_byte;
                                                            do {
                                                                received_byte = fis.read(final_buffer, total_byte_received, byte_expectex);
                                                                if (received_byte > 0){
                                                                    total_byte_received += received_byte;
                                                                    byte_expectex -= received_byte;
                                                                }
                                                                else break;
                                                            } while (byte_expectex > 0 && received_byte > 0);
                                                            if (total_byte_received == first_byte_expected){
                                                                queueCommand(Tools.combine(
                                                                        "1904".getBytes(StandardCharsets.UTF_16LE),
                                                                        (s.id).getBytes(StandardCharsets.UTF_16LE),
                                                                        Tools.data_with_ASCII_byte(String.valueOf(s.num)).getBytes(StandardCharsets.US_ASCII),
                                                                        Tools.data_with_ASCII_byte(String.valueOf(offset)).getBytes(StandardCharsets.US_ASCII),
                                                                        Tools.data_with_ASCII_byte(String.valueOf(received_byte)).getBytes(StandardCharsets.US_ASCII),
                                                                        final_buffer
                                                                    )
                                                                );
                                                            }
                                                            offset += total_byte_received;
                                                            try
                                                            {
                                                                // this method is synchronized, its parameters must be volatile
                                                                Program.mainform.panelChats.get(s.id).messages.get(s.num).changeTextUpload((byte)(100 * offset / fileSize));
                                                            }
                                                            catch (Exception ex)
                                                            {
                                                                //ex.printStackTrace();
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            catch (Exception e){
                                                e.printStackTrace();
                                            }
                                            System.out.println("File " + fileName + " sent");
                                        }
                                        else {
                                            Program.mainform.panelChats.get(s.id).filesToSend.add(file);
                                        }
                                    }
                                }
                            }
                        }
                        catch (Exception e){
                            e.printStackTrace();
                        }
                        finally{
                            sendFileWorker.set(0);
                        }
                    }
                }).start();
            }
            catch (Exception e){
                e.printStackTrace();
                try{
                    sendFileWorker.set(0);
                }
                catch(Exception ex){}
            }
        }
    }
 
    public static void queueCommand(byte[] command){
        commands.add(command);
        ping();
        addWorkerThread();
    }

    private static void addWorkerThread(){
        if (0 == workerAdded.getAndSet(1)){
            try{
                new Thread(() -> {
                    try{
                        while(!commands.isEmpty()){
                            byte[] command = commands.poll();
                            dos.write(command);
                            ping();
                        }
                        ping();
                        workerAdded.set(0);
                        System.out.println("Worker thread stopped");
                    }
                    catch(Exception e){
                        e.printStackTrace();
                        workerAdded.set(0);
                    }
                }).start();
            }
            catch (Exception e){
                e.printStackTrace();
                try{
                    workerAdded.set(0);
                }
                catch (Exception ex){}
            }
        }
    }

    public static void ping(){
        Thread thread = new Thread(new Runnable(){
            @Override
            public void run(){
                try{
                    try(SSLSocket client = (SSLSocket)ssf.createSocket(SERVER_ADDRESS, SERVER_PORT)){
                        client.getOutputStream().write(Tools.combine("0012".getBytes(StandardCharsets.UTF_16LE), user.id.getBytes(StandardCharsets.US_ASCII)));
                        System.out.println("Pinged");
                    }
                }
                catch (Exception e){
                    //e.printStackTrace();
                }
            }
        });
        thread.start();
    }

    private static void logOut(){
        if (user != null) user.state = 0;
        tempName = null;
        imgString = null;
        user = null;
        availableSlots = new ConcurrentLinkedQueue<Slot>();
        commands = new ConcurrentLinkedQueue<byte[]>();
        try {
            dis.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        try {
            dos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        try {
            client.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.gc();
    }

    public static void changeName(){
        if (tempName != null && !tempName.isEmpty()){
            user.name = tempName;
        } 
        tempName = null;
    }
 
    public static void executeClient(){
        try{
            while (user != null && (user.state == 1 || user.state == 2)){
                try{
                    if (client.isConnected()){
                        receiveFromId(client);
                    }
                    else {
                        logOut();
                    }
                }
                catch (Exception e){
                    e.printStackTrace();
                }
            }
            logOut();
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }
 
 
    public static boolean tryLogin(String username, String password){
        try {
            commands = new ConcurrentLinkedQueue<byte[]>();
            System.out.println(username + "\n" + password);
            client = (SSLSocket) ssf.createSocket(SERVER_ADDRESS, SERVER_PORT);
            System.out.println("HASH: " + client.hashCode());
            dis = new DataInputStream(client.getInputStream());
            dos = new DataOutputStream(client.getOutputStream());
            queueCommand(("0010" + Tools.data_with_unicode_byte(username) + Tools.data_with_unicode_byte(password)).getBytes(StandardCharsets.UTF_16LE));
            
            receiveFromId(client);
            if (user == null){
                System.out.println("null user");
                queueCommand("0004".getBytes(StandardCharsets.UTF_16LE));
                ping();
                throw new Exception("Login failed");
            }
            MainUI.currentID = user.id;
            if (!loginResult){
                return false;
            }
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            try {
                dis.close();
            } catch (IOException e1) {
                e1.printStackTrace();
            }
            try {
                dos.close();
            } catch (IOException e1) {
                e1.printStackTrace();
            }
            try {
                client.close();
            } catch (IOException e1) {
                e1.printStackTrace();
            }
            dos = null;
            dis = null;
            client = null;
            return false;
        }
    }

    public static void sendToId(String id, String myId, String str){
        if (myId.length() != 19 || id.length() != 19){
            return;
        }
        queueCommand(("1901"+Tools.data_with_unicode_byte(id+str)).getBytes(StandardCharsets.UTF_16LE));
    } 
 
    private static void receiveFromId(SSLSocket client){
        try{
            String instruction = Tools.receive_unicode(dis, 8);
            System.out.println(instruction);
            switch(instruction){
                // log in failed
                case "-200":{
                    loginResult = false;
                }
                break;

                // log in success
                case "0200":{
                    user = new Account();
                    System.out.println(user == null);
                    user.id = Tools.receive_unicode(dis, 38);
                    System.out.println("ID: "+ user.id);
                    user.name = Tools.receive_Unicode_Automatically(dis);
                    String priv = Tools.receive_unicode(dis, 10);
                    user.priv = Boolean.parseBoolean(priv);
                    user.state = 1;
                    // set initial private option (on or off) from here
                    // or not, if you don't have to
                    try{
                        // this method is synchronized, its parameters must be volatile
                        SwingUtilities.invokeLater(new Runnable(){
                            @Override
                            public void run(){
                                Program.mainform.formSettings.changeIncognitoMode(user.priv);

                            }
                        });
                    }
                    catch (Exception e){
                        e.printStackTrace();
                    }
                } break;

                // this id is offline
                case "0404":{
                    String offline_id = Tools.receive_unicode(dis, 38);
                    try{
                        // this method is synchronized, its parameters must be volatile
                        SwingUtilities.invokeLater(new Runnable(){
                            @Override
                            public void run(){
                            Program.mainform.turnContactActiveState(offline_id, (byte)0);
                            }
                        });
                    }
                    catch (Exception e){
                        e.printStackTrace();
                    }
                } break;

                // avatar received, not yet loaded
                case "0601":{
                    imgString = Tools.receive_ASCII_Automatically(dis);
                } break;

                // me seen
                case "0708":{
                    String id = Tools.receive_unicode(dis, 38);
                    String boolStr = Tools.receive_unicode(dis, 2);
                    SwingUtilities.invokeLater(new Runnable(){
                        @Override
                        public void run(){
                            if (boolStr.equals("0") && Program.mainform.panelChats.get(id).isLastMessageFromYou()){
                                // this method is synchronized, its parameters must be volatile
                                Program.mainform.contactItems.get(id).setUnread(false);
                            }
                            else if (boolStr.equals("0") && !Program.mainform.panelChats.get(id).isLastMessageFromYou()){
                                // this method is synchronized, its parameters must be volatile
                                Program.mainform.contactItems.get(id).setUnread(true);
                            }
                            else{
                                // this method is synchronized, its parameters must be volatile
                                Program.mainform.contactItems.get(id).setUnread(false);
                            }
                        }
                    });
                } break;

                // new account created successfully
                case "1011":{
                    System.out.println("new account created");
                    AFriendClient.instruction = "1011";
                } break;

                // name changed successfully
                case "1012":{
                    System.out.println("name changed");
                    changeName();
                    SwingUtilities.invokeLater(new Runnable(){
                        @Override
                        public void run(){
                        Program.mainform.formSettings.changeSettingsWarning("Name changed successfully!", new Color(37, 75, 133));
                    }});
                    // this method is synchronized, its parameters must be volatile
                } break;

                case "1060":{
                    String panelId = Tools.receive_unicode(dis, 38);
                    String friendAvatar = Tools.receive_ASCII_Automatically(dis);
                    if (friendAvatar!=null && !friendAvatar.isEmpty()){
                        byte[] avatar = Base64.getDecoder().decode(friendAvatar);
                        BufferedImage img = ImageIO.read(new ByteArrayInputStream(avatar));
                        
                        SwingUtilities.invokeLater(new Runnable(){
                            @Override
                            public void run(){
                                Program.mainform.setAvatar(panelId, img);   
                            }
                        });
                        // this method is synchronized, its parameters must be volatile
                    }
                } break;

                // username exists
                case "1111":{
                    System.out.println("username exists");
                } break;
                
                // addcontact
                case "1609":{
                    String data_found = Tools.receive_Unicode_Automatically(dis);
                    String[] found = data_found.split(" ");
                    System.out.println(String.join(" ", found));
                    try{
                        SwingUtilities.invokeLater(new Runnable(){
                            @Override
                            public void run(){
                                
                                String name = "";
                                for (int i = 2; i < found.length - 2; i++){
                                    name += found[i] + " ";
                                }
                                name = name.trim();
                                byte state = Byte.parseByte(found[found.length - 2]);
                                byte type = Byte.parseByte(found[found.length - 1]);
                                // this method is synchronized, its parameters must be volatile
                                Program.mainform.changeWarning("New contact added!", new Color(143, 228, 185));
                                
                                // this method is synchronized, its parameters must be volatile
                                Program.mainform.addContactItem(new Account(found[1], name, found[0], state, type));
                                if (first.containsKey(found[0])){
                                    for(MessageObject msgobj: first.get(found[0])){
                                        // this method is synchronized, its parameters must be volatile
                                        Program.mainform.panelChats.get(found[0]).addMessage(msgobj);
                                    }
                                    first.remove(found[0]);
                                }
                            }
                        });
                    }
                    catch(Exception e){
                        e.printStackTrace();
                    }
                    queueCommand(("1060" + found[0]).getBytes(StandardCharsets.UTF_16LE));
                }
                break;

                case "1610":{
                    String data_found = Tools.receive_Unicode_Automatically(dis);
                    String[] found = data_found.split(" ");
                    System.out.println(String.join(" ", found));
                    try{
                        SwingUtilities.invokeLater(new Runnable(){
                            @Override
                            public void run(){
                                
                                String name = "";
                                for (int i = 2; i < found.length - 1; i++){
                                    name += found[i] + " ";
                                }
                                name = name.trim();
                                byte state = Byte.parseByte(found[found.length - 1]);
                                byte type = 0;
                                // this method is synchronized, its parameters must be volatile
                                Program.mainform.changeWarning("New contact added!", new Color(143, 228, 185));
                                
                                // this method is synchronized, its parameters must be volatile
                                Program.mainform.addContactItem(new Account(found[1], name, found[0], state, type));
                                if (first.containsKey(found[0])){
                                    for(MessageObject msgobj: first.get(found[0])){
                                        // this method is synchronized, its parameters must be volatile
                                        Program.mainform.panelChats.get(found[0]).addMessage(msgobj);
                                    }
                                    first.remove(found[0]);
                                }
                            }
                        });
                    }
                    catch(Exception e){
                        e.printStackTrace();
                    }
                    queueCommand(("1060" + found[0]).getBytes(StandardCharsets.UTF_16LE));
                }
                break;

                case "1901":{
                    String json = Tools.receive_Unicode_Automatically(dis);
                    MessageObject msgobj = Program.gson.fromJson(json, MessageObject.class);
                    String sender = msgobj.id1;
                    if (user.id.equals(msgobj.id2)){ // if me = user2 add user1
                        if (Program.mainform.isThisPersonAdded(msgobj.id1)){
                            SwingUtilities.invokeLater(new Runnable(){
                                @Override
                                public void run(){
                                Program.mainform.panelChats.get(msgobj.id1).addMessage(msgobj);
                                if (!msgobj.sender){
                                    // this method is synchronized, its parameters must be volatile
                                    Program.mainform.turnContactActiveState(msgobj.id1, (byte)1);
                                }
                                }
                            });
                        }
                        else {
                            if (first.containsKey(sender)){
                                first.get(sender).add(msgobj);
                            }
                            else{
                                first.put(sender, new ArrayList<MessageObject>(){
                                    {
                                        add(msgobj);
                                    }
                                });
                                queueCommand(("0609" + sender).getBytes(StandardCharsets.UTF_16LE));
                            }
                        }
                    }
                    else if (user.id.equals(msgobj.id1)){
                        if (Program.mainform.isThisPersonAdded(msgobj.id2)){
                            SwingUtilities.invokeLater(new Runnable(){
                                @Override
                                public void run(){
                                Program.mainform.panelChats.get(msgobj.id2).addMessage(msgobj);
                                if (!msgobj.sender){
                                    // this method is synchronized, its parameters must be volatile
                                    Program.mainform.turnContactActiveState(msgobj.id2, (byte)1);
                                }}
                            });
                        }
                        else {
                            if (first.containsKey(sender)){
                                first.get(sender).add(msgobj);
                            }
                            else{
                                first.put(sender, new ArrayList<MessageObject>(){
                                    {
                                        add(msgobj);
                                    }
                                });
                                queueCommand(("0609" + sender).getBytes(StandardCharsets.UTF_16LE));
                            }
                        }
                    }
                } break;

                case "1903":{
                    String receiverId = Tools.receive_unicode(dis, 38);
                    String numSlotStr = Tools.receive_ASCII_Automatically(dis);
                    long numSlot = Long.parseLong(numSlotStr);
                    String name = Tools.receive_Unicode_Automatically(dis);
                    String lengthStr = Tools.receive_ASCII_Automatically(dis);
                    long length = Long.parseLong(lengthStr);
                    queueSlot(receiverId, numSlot, name, length);
                } break;

                case "1904":{
                    String receiverId = Tools.receive_unicode(dis, 38);
                    String numStr = Tools.receive_ASCII_Automatically(dis);
                    long num = Long.parseLong(numStr);
                    String offsetStr = Tools.receive_ASCII_Automatically(dis);
                    long offset = Long.parseLong(offsetStr);
                    if (offset < 0){
                        String id1, id2;
                        if (user.id.compareTo(receiverId) <= 0)
                        {
                            id1 = user.id;
                            id2 = receiverId;
                        }
                        else
                        {
                            id1 = receiverId;
                            id2 = user.id;
                        }
                        String filename = id1 + "_" + id2 + "_" + num + ".";
                        System.out.println("Deleting file: " + filename);
                        if (files.containsKey(filename)){
                            try{
                                try{
                                    files.get(filename).fis.close();
                                }
                                catch (Exception e){}
                                try{
                                    files.get(filename).fos.close();
                                }
                                catch (Exception e){}
                                String file = files.get(filename).name;
                                files.remove(filename);
                                Files.delete(Path.of(file));
                            }
                            catch (Exception e){
                                e.printStackTrace();
                            }
                        }
                    }
                    else {
                        String receivedByteStr = Tools.receive_ASCII_Automatically(dis);
                        int receivedByte = Integer.parseInt(receivedByteStr);
                        byte[] databyte = Tools.receive_byte_array(dis, receivedByte);
                        String id1, id2;
                        if (user.id.compareTo(receiverId) <= 0)
                        {
                            id1 = user.id;
                            id2 = receiverId;
                        }
                        else
                        {
                            id1 = receiverId;
                            id2 = user.id;
                        }
                        String filename = id1 + "_" + id2 + "_" + num + ".";
                        System.out.println("File: " + filename);
                        if (files.containsKey(filename)){
                            writeCommands.add(new WriteCommand(filename, offset, receivedByte, databyte));
                            addWriteThread();
                        }
                    }
                } break;

                case "1905":{
                    String receiverId = Tools.receive_unicode(dis, 38);
                    String numStr = Tools.receive_ASCII_Automatically(dis);
                    String sizeStr = Tools.receive_ASCII_Automatically(dis);
                    long size = Long.parseLong(sizeStr);
                    String id1, id2;
                    if (user.id.compareTo(receiverId) <= 0)
                    {
                        id1 = user.id;
                        id2 = receiverId;
                    }
                    else
                    {
                        id1 = receiverId;
                        id2 = user.id;
                    }
                    String file = id1 + "_" + id2 + "_" + numStr + ".";
                    if (files.containsKey(file)){
                        files.get(file).size += size;
                        SwingUtilities.invokeLater(new Runnable(){
                            @Override
                            public void run(){
                            Program.mainform.panelChats.get(receiverId).messages.get(Long.parseLong(numStr)).startTimer(file, size);
                        }});
                        if (files.get(file).size == 0){
                            files.remove(file);
                        }
                    }
                } break;

                case "2002":{
                    String panelId = Tools.receive_unicode(dis, 38);
                    String messageNumberStr = Tools.receive_Unicode_Automatically(dis);
                    Long messageNumber = Long.parseLong(messageNumberStr);
                    if (Program.mainform.panelChats.containsKey(panelId)){
                        System.out.println("deleting: " + messageNumber);
                        SwingUtilities.invokeLater(new Runnable(){
                            @Override
                            public void run(){
                            Program.mainform.panelChats.get(panelId).removeMessage(messageNumber);

                        }});
                    }
                } break;

                case "2004":{
                    System.out.println("You are logged in from another device");
                    user.state = 0;
                    SwingUtilities.invokeLater(new Runnable(){
                        @Override
                        public void run(){
                            Program.mainform.showLogin();
                    }});
                } break;

                // this id is online
                case "2211":{
                    String id = Tools.receive_unicode(dis, 38);
                    SwingUtilities.invokeLater(new Runnable(){
                        @Override
                        public void run(){
                        Program.mainform.turnContactActiveState(id, (byte)1);
                }});
                    
                } break;

                // sort contact list
                case "2411":{
                    SwingUtilities.invokeLater(new Runnable(){
                        @Override
                        public void run(){

                        Program.mainform.formLoading.showProgress(100);
                        Program.mainform.sortContactItems();
                }});
                } break;

                // add contact failed
                case "2609":{
                    String id = Tools.receive_unicode(dis, 38);
                    SwingUtilities.invokeLater(new Runnable(){
                        @Override
                        public void run(){
                        Program.mainform.changeWarning("That ID doesn't exist", new Color(255, 0, 0));
                        }
                    });
                } break;

                // change password successfully
                case "4269":{
                    System.out.println("Change password successfully");
                    SwingUtilities.invokeLater(new Runnable(){
                        @Override
                        public void run(){

                            Program.mainform.formSettings.changeSettingsWarning("Change password successfully", new Color(143, 228, 185));                        }
                    });
                } break;

                // load messages
                case "6475":{
                    String panelId = Tools.receive_unicode(dis, 38);
                    String json = Tools.receive_Unicode_Automatically(dis);
                    System.out.println("Old messages have arrived");
                    MessageObject[] messageObjects = Program.gson.fromJson(json, MessageObject[].class);
                    // wrap messageObjects with list 

                    try{
                        SwingUtilities.invokeLater(new Runnable(){
                            @Override
                            public void run(){
                                Program.mainform.panelChats.get(panelId).loadMessages(Arrays.asList(messageObjects));

                            }
                        });
                    }
                    catch (Exception e){
                        e.printStackTrace();
                    }
                    queueCommand(("0708" + panelId).getBytes(StandardCharsets.UTF_16LE));
                } break;

                case "7351":{
                    String stateStr = Tools.receive_unicode(dis, 2);
                    byte state = Byte.parseByte(stateStr);
                    publicState = state;
                } break;

                // old password is not correct
                case "9624":{
                    System.out.println("Old password is not correct");
                    SwingUtilities.invokeLater(new Runnable(){
                        @Override
                        public void run(){
                            Program.mainform.formSettings.changeSettingsWarning("Old password is not correct", new Color(213, 54, 41));

                        }
                    });
                } break;

                default:{
                    System.out.println("command not found");
                }
                break;
            }
        }
        catch (Exception e){
            e.printStackTrace();
            if(e.getMessage().contains("Socket")) try {if (user != null) user.state = 0;} catch (Exception ex){}
        }
    }

    public static boolean signedUp(String username, String pw){
        try{
            boolean success = false;

            client = (SSLSocket) ssf.createSocket(SERVER_ADDRESS, SERVER_PORT);
            System.out.println("HASH: " + client.hashCode());
            dis = new DataInputStream(client.getInputStream());
            dos = new DataOutputStream(client.getOutputStream());
            queueCommand(("0011"+Tools.data_with_unicode_byte(username) + Tools.data_with_unicode_byte(pw)).getBytes(StandardCharsets.UTF_16LE));
            receiveFromId(client);
            if (instruction.equals("1011")){
                success = true;
            }
            else if (instruction.equals("1111")){
                
            }
            queueCommand("2004".getBytes(StandardCharsets.UTF_16LE));
            try{
                dis.close();
            }
            catch(Exception e){}
            try{
                dos.close();
            }
            catch(Exception e){}
            try{
                client.close();
            }
            catch(Exception e){}
            client = null;
            dos = null;
            dis = null;
            return success;
        }
        catch (Exception e){
            e.printStackTrace();
            try {
                dis.close();
            } catch (IOException e1) {}
            try {
                dos.close();
            } catch (IOException e1) {}
            try {
                client.close();
            } catch (IOException e1) {}
            client = null;
            dos = null;
            dis = null;
            return false;
        }
    }
}
