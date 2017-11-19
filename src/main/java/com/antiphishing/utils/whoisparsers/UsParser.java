package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;
/**
 * Created by dell on 2017/11/16.
 */
/**
 * Domain Name: test.us
 Registry Domain ID: D1769431-US
 Registrar WHOIS Server: whois.opensrs.net
 Registrar URL: www.opensrs.com
 Updated Date: 2016-08-10T13:14:31Z
 Creation Date: 2002-04-24T14:00:37Z
 Registry Expiry Date: 2018-04-23T23:59:59Z
 Registrar: Tucows Domains Inc.
 Registrar IANA ID: 69
 Registrar Abuse Contact Email:
 Registrar Abuse Contact Phone:
 Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
 Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
 Registry Registrant ID: C54050456-US
 Registrant Name: Steve Curry
 Registrant Organization:
 Registrant Street: 714-10 Milner Business Court
 Registrant Street:
 Registrant Street:
 Registrant City: Scarborough
 Registrant State/Province: ON
 Registrant Postal Code: M1B3C6
 Registrant Country: CA
 Registrant Phone: +1.4164841461
 Registrant Phone Ext:
 Registrant Fax:
 Registrant Fax Ext:
 Registrant Email: steve@wideport.com
 Registrant Application Purpose: P3
 Registrant Nexus Category: C11
 Registry Admin ID: C54050454-US
 Admin Name: Steve Curry
 Admin Organization:
 Admin Street: 714-10 Milner Business Court
 Admin Street:
 Admin Street:
 Admin City: Scarborough
 Admin State/Province: ON
 Admin Postal Code: M1B3C6
 Admin Country: CA
 Admin Phone: +1.4164841461
 Admin Phone Ext:
 Admin Fax:
 Admin Fax Ext:
 Admin Email: steve@wideport.com
 Admin Application Purpose: P3
 Admin Nexus Category: C11
 Registry Tech ID: C54050457-US
 Tech Name: Steve Curry
 Tech Organization:
 Tech Street: 714-10 Milner Business Court
 Tech Street:
 Tech Street:
 Tech City: Scarborough
 Tech State/Province: ON
 Tech Postal Code: M1B3C6
 Tech Country: CA
 Tech Phone: +1.4164841461
 Tech Phone Ext:
 Tech Fax:
 Tech Fax Ext:
 Tech Email: admin@wideport.com
 Tech Application Purpose: P3
 Tech Nexus Category: C11
 Name Server: ns3.systemdns.com
 Name Server: ns1.systemdns.com
 Name Server: ns2.systemdns.com
 DNSSEC: unsigned
 URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
 >>> Last update of WHOIS database: 2017-11-16T02:59:07Z <<<

 For more information on Whois status codes, please visit https://icann.org/epp
 */
public class UsParser extends AParser{
    private UsParser(){}

    private static UsParser instance = null;

    public static UsParser getInstance(){
        if(instance == null){
            instance = new UsParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*Domain Name:\\s*[^\\n]+";
    private final String CONTACTSREG = "\\s*Registrant Name:\\s*[^\\n]+";
    private final String ORGREG = "\\s*Registrant Organization:\\s*[^\\n]+";
    private final String CTIMEREG = "\\s*Creation Date:\\s*[^\\n]+";
    private final String UTIMEREG = "\\s*Updated Date:\\s*[^\\n]+";
    private final String EMAILREG = "\\s*Admin Email:\\s*[^\\n]+";
    private final String PHONEREG = "\\s*Admin Phone:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern contactPattern = Pattern.compile(CONTACTSREG);
    private Pattern orgPattern = Pattern.compile(ORGREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEREG);
    private Pattern utimePattern = Pattern.compile(UTIMEREG);
    private Pattern emailPattern = Pattern.compile(EMAILREG);
    private Pattern phonePattern = Pattern.compile(PHONEREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try{
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
            String contacts = getFieldValue(getMatchField(contactPattern, whoisResponse), ":");
            whoisModel.setContacts(contacts);
            String orgs = getFieldValue(getMatchField(orgPattern, whoisResponse), ":");
            whoisModel.setOrgnization(orgs);
            String ctime = getFieldValue(getMatchField(ctimePattern, whoisResponse), ":");
            whoisModel.setCtime(simpleDateFormat.parse(ctime).getTime());
            String utime = getFieldValue(getMatchField(utimePattern, whoisResponse), ":");
            whoisModel.setUtime(simpleDateFormat.parse(utime).getTime());
            String email = getFieldValue(getMatchField(emailPattern, whoisResponse), ":");
            whoisModel.setEmail(email);
            String phone = getFieldValue(getMatchField(phonePattern, whoisResponse), ":");
            whoisModel.setPhone(phone);
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
