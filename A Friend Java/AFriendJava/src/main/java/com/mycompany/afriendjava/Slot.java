package com.mycompany.afriendjava;

public class Slot {
    public long num;
    public String id;
    public String name;
    public long length;

    public Slot(String id, long num, String name, long length)
    {
        this.id = id;
        this.num = num;
        this.name = name;
        this.length = length;
    }

    public Slot() { }
}
