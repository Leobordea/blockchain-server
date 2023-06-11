package com.mycompany.afriendjava;

import java.sql.Timestamp;

public class MessageObject {
    public String id1;
    public String id2;
    public long messagenumber;
    public Timestamp timesent;
    public boolean sender;
    public String message;
    public byte type;

    public MessageObject(String id1, String id2, long messagenumber, Timestamp timesent, boolean sender, String message, byte type) {
        this.id1 = id1;
        this.id2 = id2;
        this.messagenumber = messagenumber;
        this.timesent = timesent;
        this.sender = sender;
        this.message = message;
        this.type = type;
    }
    
    public MessageObject(){}
}
