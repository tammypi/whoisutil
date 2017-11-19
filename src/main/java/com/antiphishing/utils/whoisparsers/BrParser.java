package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;
/**
 * Created by dell on 2017/11/16.
 */

/**
 * % Copyright (c) Nic.br
 %  The use of the data below is only permitted as described in
 %  full by the terms of use at https://registro.br/termo/en.html ,
 %  being prohibited its distribution, commercialization or
 %  reproduction, in particular, to use it for advertising or
 %  any similar purpose.
 %  2017-11-16 05:55:57 (BRST -02:00)

 domain:      uol.com.br
 owner:       Universo Online S.A.
 owner-c:     CAU12
 admin-c:     CAU12
 tech-c:      CTU6
 billing-c:   CCU10
 nserver:     eliot.uol.com.br 200.221.11.98
 nsstat:      20171113 AA
 nslastaa:    20171113
 nserver:     borges.uol.com.br 200.147.255.105
 nsstat:      20171113 AA
 nslastaa:    20171113
 nserver:     charles.uol.com.br 200.147.38.8
 nsstat:      20171113 AA
 nslastaa:    20171113
 created:     19960424 #7137
 changed:     20170106
 expires:     20230424
 status:      published

 nic-hdl-br:  CAU12
 person:      Contato Administrativo - UOL
 created:     20031202
 changed:     20170106

 nic-hdl-br:  CCU10
 person:      Contato de Cobranca - UOL
 created:     20031202
 changed:     20170112

 nic-hdl-br:  CTU6
 person:      Contato Tecnico - UOL
 created:     20031202
 changed:     20170106

 % Security and mail abuse issues should also be addressed to
 % cert.br, http://www.cert.br/ , respectivelly to cert@cert.br
 % and mail-abuse@cert.br
 %
 % whois.registro.br accepts only direct match queries. Types
 % of queries are: domain (.br), registrant (tax ID), ticket,
 % provider, contact handle (ID), CIDR block, IP and ASN.
 */
public class BrParser extends AParser{
    private BrParser(){}

    private static BrParser instance = null;

    public static BrParser getInstance(){
        if(instance == null){
            instance = new BrParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*domain:\\s*[^\\n]+";
    private final String CONTACTSREG = "\\s*owner:\\s*[^\\n]+";
    private final String CTIMEEG = "\\s*created:\\s*[^\\n]+";
    private final String UTIMEREG = "\\s*changed:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern contactsPattern = Pattern.compile(CONTACTSREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEEG);
    private Pattern utimePattern = Pattern.compile(UTIMEREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyyMMdd");

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
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
