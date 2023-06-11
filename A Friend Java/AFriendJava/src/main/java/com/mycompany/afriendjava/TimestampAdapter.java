package com.mycompany.afriendjava;

import java.sql.Timestamp;

import com.google.gson.TypeAdapter;

public class TimestampAdapter extends TypeAdapter<Timestamp> {
    @Override
    public void write(com.google.gson.stream.JsonWriter out, Timestamp value) throws java.io.IOException {
        out.value(value.getTime());
    }

    @Override
    public Timestamp read(com.google.gson.stream.JsonReader in) throws java.io.IOException {
        return new Timestamp(in.nextLong());
    }
}
