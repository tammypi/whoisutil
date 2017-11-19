package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;
/**
 * Created by dell on 2017/11/17.
 */
/**
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
 # the .se top level domain.
 # This whois printout is printed with UTF-8 encoding.
 #
 state:            active
 domain:           posten.se
 holder:           CP0000-22537
 admin-c:          dipcon0903-00017
 tech-c:           dipcon0903-00017
 billing-c:        dipcon0903-00017
 created:          2005-04-11
 modified:         2017-08-09
 expires:          2018-04-11
 transferred:      2009-03-07
 nserver:          dns03.ports.se
 nserver:          dns02.ports.se
 nserver:          dns01.dipcon.com
 nserver:          ns2.p10.dynect.net
 nserver:          ns1.p10.dynect.net
 dnssec:           unsigned delegation
 status:           ok
 registrar:        Ports Group AB
 */
public class SeParser extends AParser{
    private SeParser(){}

    private static SeParser instance = null;

    public static SeParser getInstance(){
        if(instance == null){
            instance = new SeParser();
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
        try {
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
            String contacts = getFieldValue(getMatchField(contactsPattern, whoisResponse), ":");
            whoisModel.setContacts(contacts);
            String ctime = getFieldValue(getMatchField(ctimePattern, whoisResponse), ":");
            whoisModel.setCtime(simpleDateFormat.parse(ctime).getTime());
            String utime = getFieldValue(getMatchField(utimePattern, whoisResponse), ":");
            whoisModel.setUtime(simpleDateFormat.parse(utime).getTime());
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
        }catch (Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
