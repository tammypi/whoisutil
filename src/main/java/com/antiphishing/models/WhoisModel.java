package com.antiphishing.models;

import java.io.Serializable;
import java.text.SimpleDateFormat;

/**
 * Created by dell on 2017/11/14.
 */
public class WhoisModel implements Serializable{
    private String domain;
    private String ip;
    private String contacts;
    private String phone;
    private String email;
    private long ctime;
    private long utime;
    private String orgnization;

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public String getContacts() {
        return contacts;
    }

    public void setContacts(String contacts) {
        this.contacts = contacts;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public long getCtime() {
        return ctime;
    }

    public void setCtime(long ctime) {
        this.ctime = ctime;
    }

    public long getUtime() {
        return utime;
    }

    public void setUtime(long utime) {
        this.utime = utime;
    }

    public String getOrgnization() {
        return orgnization;
    }

    public void setOrgnization(String orgnization) {
        this.orgnization = orgnization;
    }

    public String toString(){
        StringBuilder sb = new StringBuilder();
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        sb.append("domain:"+(getDomain()==null?"":getDomain())+"\n");
        sb.append("contacts:"+(getContacts()==null?"":getContacts())+"\n");
        sb.append("orgnization:"+(getOrgnization()==null?"":getOrgnization())+"\n");
        sb.append("ip:"+(getIp()==null?"":getIp())+"\n");
        if(getCtime() != 0){
            sb.append("ctime:"+simpleDateFormat.format(getCtime()) + "\n");
        }else{
            sb.append("ctime:\n");
        }
        if(getUtime() != 0){
            sb.append("utime:"+simpleDateFormat.format(getUtime())+"\n");
        }else{
            sb.append("utime:\n");
        }
        sb.append("email:"+(getEmail()==null?"":getEmail())+"\n");
        sb.append("phone:"+(getPhone()==null?"":getPhone()) + "\n");
        return sb.toString();
    }
}
