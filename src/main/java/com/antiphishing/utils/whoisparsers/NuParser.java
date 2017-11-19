package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;
/**
 * Created by dell on 2017/11/16.
 */

/***
 * # Copyright (c) 1997- IIS (The Internet Foundation In Sweden).
 # All rights reserved.
 # The information obtained through searches, or otherwise, is protected
 # by the Swedish Copyright Act (1960:729) and international conventions.
 # It is also subject to database protection according to the Swedish
 # Copyright Act.
 # Any use of this material to target advertising or
 # similar activities is forbidden and will be prosecuted.
 # If any of the information below is transferred to a third
 # party, it must be done in its entirety. This server must
 # not be used as a backend for a search engine.
 # Result of search for registered domain names under
 # the .nu top level domain.
 # This whois printout is printed with UTF-8 encoding.
 #
 state:            active
 domain:           aaa.nu
 holder:           ha1bdur8dq
 admin-c:          ha1bdur8dq
 tech-c:           l8pkgkwyxd
 billing-c:        ha1bdur8dq
 created:          2004-06-02
 modified:         2017-05-22
 expires:          2018-06-02
 nserver:          ns01.hostcontrol.com
 nserver:          ns02.hostcontrol.com
 dnssec:           unsigned delegation
 status:           ok
 registrar:        NuNames.nu
 */
public class NuParser extends AParser{
    private NuParser(){}

    private static NuParser instance = null;

    public static NuParser getInstance(){
        if(instance == null){
            instance = new NuParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*domain:\\s*[^\\n]+";
    private final String CONTACTSREG = "\\s*admin\\-c:\\s*[^\\n]+";
    private final String CTIMEREG = "\\s*created:\\s*[^\\n]+";
    private final String UTIMEREG = "\\s*modified:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern contactsPattern = Pattern.compile(CONTACTSREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEREG);
    private Pattern utimePattern = Pattern.compile(UTIMEREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd");

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try{
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
            String contacts = getFieldValue(getMatchField(contactsPattern, whoisResponse), ":");
            whoisModel.setContacts(contacts);
            String ctime = getFieldValue(getMatchField(ctimePattern, whoisResponse), ":");
            whoisModel.setCtime(simpleDateFormat.parse(ctime).getTime());
            String utime = getFieldValue(getMatchField(utimePattern, whoisResponse), ":");
            whoisModel.setUtime(simpleDateFormat.parse(utime).getTime());
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
