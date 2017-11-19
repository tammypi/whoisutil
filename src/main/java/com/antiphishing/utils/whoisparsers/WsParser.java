package com.antiphishing.utils.whoisparsers;

import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;

/**
 * Created by dell on 2017/11/17.
 */
/**
 * Domain Name: TEST.WS
 Registry Domain ID: D865CD2A2A01835CE040010AAB015FFF
 Registrar WHOIS Server: whois.website.ws
 Registrar URL: http://www.website.ws/
 Updated Date: 2015-11-03
 Creation Date: 2003-03-09
 Registrar Registration Expiration Date: 2021-03-09
 Registrar: GLOBAL DOMAINS INTERNATIONAL
 Registrar IANA ID: 1463
 Registrar Abuse Contact Email: abuse@website.ws
 Registrar Abuse Contact Phone: +1.7606023000
 Domain Status: ok
 Registry Registrant ID:
 Registrant Name: Private Domain Registrations
 Registrant Organization:
 Registrant Street: 701 Palomar Airport Rd, Suite 300
 Registrant City: Carlsbad
 Registrant State/Province: CA
 Registrant Postal Code: 92011
 Registrant Country: US
 Registrant Phone: +1.7606023000
 Registrant Phone Ext:
 Registrant Fax:
 Registrant Fax Ext:
 Registrant Email: test.ws@privatedomainregistrations.ws
 Registry Admin ID:
 Admin Name: Private Domain Registrations
 Admin Organization:
 Admin Street: 701 Palomar Airport Rd, Suite 300
 Admin City: Carlsbad
 Admin State/Province: CA
 Admin Postal Code: 92011
 Admin Country: US
 Admin Phone: +1.7606023000
 Admin Phone Ext:
 Admin Fax:
 Admin Fax Ext:
 Admin Email: test.ws@privatedomainregistrations.ws
 Registry Tech ID:
 Tech Name: Private Domain Registrations
 Tech Organization:
 Tech Street: 701 Palomar Airport Rd, Suite 300
 Tech City: Carlsbad
 Tech State/Province: CA
 Tech Postal Code: 92011
 Tech Country: US
 Tech Phone: +1.7606023000
 Tech Phone Ext:
 Tech Fax:
 Tech Fax Ext:
 Tech Email: test.ws@privatedomainregistrations.ws
 Name Server: fwd1.dns.ws
 Name Server: fwd2.dns.ws
 Name Server: fwd3.dns.ws
 Name Server: fwd4.dns.ws
 DNSSEC: unsigned
 URL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/
 >>> Last update of WHOIS database: 2017-11-17 <<<
 */
public class WsParser extends AParser{
    private WsParser(){}

    private static WsParser wsParser = null;

    public static WsParser getInstance(){
        if(wsParser == null){
            wsParser = new WsParser();
        }
        return wsParser;
    }

    private final String DOMAINREG = "\\s*Domain Name:\\s*[^\\n]+";
    private final String CONTACTSREG = "\\s*Registrant Name:\\s*[^\\n]+";
    private final String ORGREG = "\\s*Registrant Name:\\s*[^\\n]+";
    private final String EMAILREG = "\\s*Registrant Email:\\s*[^\\n]+";
    private final String PHONEREG = "\\s*Registrant Phone:\\s*[^\\n]+";
    private final String CTIMEREG = "\\s*Creation Date:\\s*[^\\n]+";
    private final String UTIMEREG = "\\s*Updated Date:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern contactsPattern = Pattern.compile(CONTACTSREG);
    private Pattern orgPattern = Pattern.compile(ORGREG);
    private Pattern emailPattern = Pattern.compile(EMAILREG);
    private Pattern phonePattern = Pattern.compile(PHONEREG);
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
            String org = getFieldValue(getMatchField(orgPattern, whoisResponse), ":");
            whoisModel.setOrgnization(org);
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
            String email = getFieldValue(getMatchField(emailPattern, whoisResponse), ":");
            whoisModel.setEmail(email);
            String phone = getFieldValue(getMatchField(phonePattern, whoisResponse), ":");
            whoisModel.setPhone(phone);
            String ctime = getFieldValue(getMatchField(ctimePattern, whoisResponse), ":");
            whoisModel.setCtime(simpleDateFormat.parse(ctime).getTime());
            String utime = getFieldValue(getMatchField(utimePattern, whoisResponse), ":");
            whoisModel.setUtime(simpleDateFormat.parse(utime).getTime());
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
