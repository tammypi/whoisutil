package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.Locale;
import java.util.regex.Pattern;
/**
 * Created by dell on 2017/11/15.
 */

/**
 *     Domain name:
 asda.co.uk

 Registrant:
 ASDA Stores Ltd

 Registrant type:
 Unknown

 Registrant's address:
 Asda House
 Southbank, Great Wilson Street
 LEEDS
 LS11 5AD
 United Kingdom

 Data validation:
 Nominet was able to match the registrant's name and address against a 3rd party data source on 10-Dec-2012

 Registrar:
 Markmonitor Inc. t/a MarkMonitor Inc. [Tag = MARKMONITOR]
 URL: http://www.markmonitor.com

 Relevant dates:
 Registered on: before Aug-1996
 Expiry date:  25-Apr-2019
 Last updated:  28-Feb-2017

 Registration status:
 Registered until expiry date.

 Name servers:
 a1-185.akam.net
 a10-66.akam.net
 a22-67.akam.net
 pdnswm1.ultradns.net
 pdnswm2.ultradns.net
 pdnswm3.ultradns.org
 pdnswm4.ultradns.org
 pdnswm5.ultradns.info
 pdnswm6.ultradns.co.uk

 WHOIS lookup made at 07:36:22 15-Nov-2017

 --
 This WHOIS information is provided for free by Nominet UK the central registry
 for .uk domain names. This information and the .uk WHOIS are:

 Copyright Nominet UK 1996 - 2017.
 */
public class UkParser extends AParser{
    private UkParser(){}

    private static UkParser instance = null;

    public static UkParser getInstance(){
        if(instance == null){
            instance = new UkParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*Domain name:\\r\\n\\s*[^\\n]+";
    private final String CONTACTSREG = "\\s*Registrant:\\r\\n\\s*[^\\n]+";
    private final String UTIMEREG = "\\s*Last updated:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern contactPattern = Pattern.compile(CONTACTSREG);
    private Pattern utimePattern = Pattern.compile(UTIMEREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("dd-MMM-yyyy", Locale.ENGLISH);

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try{
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
            String contacts = getFieldValue(getMatchField(contactPattern, whoisResponse), ":");
            whoisModel.setContacts(contacts);
            String utime = getFieldValue(getMatchField(utimePattern, whoisResponse), ":");
            whoisModel.setUtime(simpleDateFormat.parse(utime.trim()).getTime());
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
