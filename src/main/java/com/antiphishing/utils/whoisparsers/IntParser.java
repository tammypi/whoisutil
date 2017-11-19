package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;
/**
 * Created by dell on 2017/11/16.
 */
/**
 * % IANA WHOIS server
 % for more information on IANA, visit http://www.iana.org
 % This query returned 1 object

 domain:       COE.INT

 organisation: Council of Europe
 address:      Avenue de l'Europe
 address:      Strasbourg  67000
 address:      France

 contact:      administrative
 name:         Marc ULRICH
 address:      Avenue de l'Europe
 address:      Strasbourg  67000
 address:      France
 phone:        +33388412000
 e-mail:       marc.ulrich@coe.int

 contact:      technical
 name:         Samuel CHABOISSEAU
 address:      Avenue de l'Europe
 address:      Strasbourg  67000
 address:      France
 phone:        +33388412000
 e-mail:       samuel.chaboisseau@coe.int

 nserver:      CUIVRE.COE.INT 193.164.229.94
 nserver:      NEON.COE.INT 193.164.229.99

 created:      1997-10-24
 changed:      2017-03-07
 source:       IANA
 */
public class IntParser extends AParser{
    private IntParser(){}

    private static IntParser instance = null;

    public static IntParser getInstance(){
        if(instance == null){
            instance = new IntParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*domain:\\s*[^\\n]+";
    private final String CONTACTSREG = "\\s*contact:\\s*[^\\n]+";
    private final String ORGREG = "\\s*organisation:\\s*[^\\n]+";
    private final String CTIMEREG = "\\s*created:\\s*[^\\n]+";
    private final String UTIMEREG = "\\s*changed:\\s*[^\\n]+";
    private final String EMAILREG = "\\s*e\\-mail:\\s*[^\\n]+";
    private final String PHONEREG = "\\s*phone:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern contactsPattern = Pattern.compile(CONTACTSREG);
    private Pattern orgPattern = Pattern.compile(ORGREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEREG);
    private Pattern utimePattern = Pattern.compile(UTIMEREG);
    private Pattern emailPattern = Pattern.compile(EMAILREG);
    private Pattern phonePattern = Pattern.compile(PHONEREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd");

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try {
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
            String contacts = getFieldValue(getMatchField(contactsPattern, whoisResponse), ":");
            whoisModel.setContacts(contacts);
            String org = getFieldValue(getMatchField(orgPattern, whoisResponse), ":");
            whoisModel.setOrgnization(org);
            String ctime = getFieldValue(getMatchField(ctimePattern, whoisResponse), ":");
            whoisModel.setCtime(simpleDateFormat.parse(ctime).getTime());
            String utime = getFieldValue(getMatchField(utimePattern, whoisResponse), ":");
            whoisModel.setUtime(simpleDateFormat.parse(utime).getTime());
            String email = getFieldValue(getMatchField(emailPattern, whoisResponse), ":");
            whoisModel.setEmail(email);
            String phone = getFieldValue(getMatchField(phonePattern, whoisResponse), ":");
            whoisModel.setPhone(phone);
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
        } catch (Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
