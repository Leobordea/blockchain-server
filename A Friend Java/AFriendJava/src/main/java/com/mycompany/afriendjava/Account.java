package com.mycompany.afriendjava;

public class Account {
    public String username;
    public String name;
    public String id;
    public byte state;
    public byte type;
    public boolean priv = false;

    public Account() 
    {

    }
    public Account(String username, String name, String id, byte state, byte type) 
    { 
        this.username = username;
        this.name = name;
        this.id = id;
        this.state = state;
        this.type = type;
    }
}
