package com.antiphishing.utils.whoisparsers;

/**
 * Created by dell on 2017/11/14.
 */

import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;

/****************************

 *********************************************************************
 * Please note that the following result could be a subgroup of      *
 * the data contained in the database.                               *
 *                                                                   *
 * Additional information can be visualized at:                      *
 * http://www.nic.it/cgi-bin/Whois/whois.cgi                         *
 *********************************************************************

 Domain:             aaa.it
 Status:             ok / autoRenewPeriod
 Created:            1996-06-21 00:00:00
 Last Update:        2017-11-12 00:36:55
 Expire Date:        2017-11-11

 Registrant
 Organization:     Incipit Holding s.r.l.
 Address:          Via Fatebenefratelli, 5
 Milano
 20121
 MI
 IT
 Created:          2009-12-04 15:50:17
 Last Update:      2011-03-09 11:26:07

 Admin Contact
 Name:             Incipit Holding s.r.l.
 Organization:     Incipit Holding s.r.l.
 Address:          Via Fatebenefratelli, 5
 Milano
 20121
 MI
 IT
 Created:          2009-12-04 15:50:17
 Last Update:      2011-03-09 11:26:07

 Technical Contacts
 Name:             Incipit Holding s.r.l.
 Organization:     Incipit Holding s.r.l.
 Address:          Via Fatebenefratelli, 5
 Milano
 20121
 MI
 IT
 Created:          2009-12-04 15:50:17
 Last Update:      2011-03-09 11:26:07

 Registrar
 Organization:     Neen s.r.l.
 Name:             NEEN-REG
 Web:              http://www.neen.it

 Nameservers
 ns1.bluehost.com
 ns2.bluehost.com


 */
public class ItParser extends AParser{
    private ItParser(){}
    private static ItParser instance = null;

    public static ItParser getInstance(){
        if(instance == null){
            instance = new ItParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*Domain:\\s*[^\\n]+";
    private final String CONTACTSREG = "\\sAdmin Contact\\n\\s*Name:\\s*[^\\n]+";
    private final String ORGNIZATIONREG = "\\s*Organization:\\s*[^\\n]+";
    private final String CTIMEREG = "\\s*Created:\\s*[^\\n]+";
    private final String UTIMEREG = "\\s*Last Update:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern contactPattern = Pattern.compile(CONTACTSREG);
    private Pattern orgnizationPattern = Pattern.compile(ORGNIZATIONREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEREG);
    private Pattern utimePattern = Pattern.compile(UTIMEREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try{
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
            String contacts = getFieldValue(getMatchField(contactPattern, whoisResponse), ":");
            whoisModel.setContacts(contacts);
            String orgnization = getFieldValue(getMatchField(orgnizationPattern, whoisResponse), ":");
            whoisModel.setOrgnization(orgnization);
            String ctime = getFieldValue(getMatchField(ctimePattern, whoisResponse), ":");
            whoisModel.setCtime(simpleDateFormat.parse(ctime.trim()).getTime());
            String utime = getFieldValue(getMatchField(utimePattern, whoisResponse), ":");
            whoisModel.setUtime(simpleDateFormat.parse(utime.trim()).getTime());
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
