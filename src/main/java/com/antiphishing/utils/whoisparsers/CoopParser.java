package com.antiphishing.utils.whoisparsers;

import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;

/**
 * Created by dell on 17-11-19.
 */

/**
 * Domain Name: BLUEHAWK.COOP
 Registry Domain ID: D7884175-CNIC
 Registrar WHOIS Server: whois.enterprice.net
 Registrar URL: http://www.epag.de/
 Updated Date: 2017-06-19T09:08:00.0Z
 Creation Date: 2005-05-24T10:22:17.0Z
 Registry Expiry Date: 2018-05-24T23:59:59.0Z
 Registrar: EPAG Domainservices GmbH
 Registrar IANA ID: 85
 Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
 Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
 Registry Registrant ID: C31200000-CNIC
 Registrant Name: Colleen Leppert
 Registrant Organization: Premier Distribution Cooperative DBA Blue Hawk
 Registrant Street: 4805 E Thistle Landing Dr, Suite 110
 Registrant City: Phoenix
 Registrant State/Province: AZ
 Registrant Postal Code: 85044
 Registrant Country: US
 Registrant Phone: +1.4807045015
 Registrant Fax:
 Registrant Email: colleenleppert@mac.com
 Registry Admin ID: C18215647-CNIC
 Admin Name: Colleen Leppert
 Admin Organization: Premier Distribution Coop dba Blue Hawk
 Admin Street: 4805 E Thistle Landing Dr, Suite 110
 Admin City: Phoenix
 Admin State/Province: AZ
 Admin Postal Code: 85044
 Admin Country: US
 Admin Phone: +1.4807045015
 Admin Fax: +999.999
 Admin Email: colleenleppert@mac.com
 Registry Tech ID: C18215647-CNIC
 Tech Name: Colleen Leppert
 Tech Organization: Premier Distribution Coop dba Blue Hawk
 Tech Street: 4805 E Thistle Landing Dr, Suite 110
 Tech City: Phoenix
 Tech State/Province: AZ
 Tech Postal Code: 85044
 Tech Country: US
 Tech Phone: +1.4807045015
 Tech Fax: +999.999
 Tech Email: colleenleppert@mac.com
 Name Server: NS1.DOTSTER.COM
 Name Server: NS2.DOTSTER.COM
 DNSSEC: unsigned
 Registry Billing ID: C18215647-CNIC
 Billing Name: Colleen Leppert
 Billing Organization: Premier Distribution Coop dba Blue Hawk
 Billing Street: 4805 E Thistle Landing Dr, Suite 110
 Billing City: Phoenix
 Billing State/Province: AZ
 Billing Postal Code: 85044
 Billing Country: US
 Billing Phone: +1.4807045015
 Billing Fax: +999.999
 Billing Email: colleenleppert@mac.com
 Registrar Abuse Contact Email: compliance@epag.de
 Registrar Abuse Contact Phone: +49.2283296840
 URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
 >>> Last update of WHOIS database: 2017-11-19T12:02:31.0Z <<<
 */
public class CoopParser extends AParser{
    private CoopParser(){}

    private static CoopParser instance = null;

    public static CoopParser getInstance(){
        if(instance == null){
            instance = new CoopParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*Domain Name:\\s*[^\\n]+";
    private final String CONTACTREG = "\\s*Registrant Name:\\s*[^\\n]+";
    private final String ORGREG = "\\s*Registrant Organization:\\s*[^\\n]+";
    private final String PHONEREG = "\\s*Registrant Phone:\\s*[^\\n]+";
    private final String EMAILREG = "\\s*Registrant Email:\\s*[^\\n]+";
    private final String CTIMEREG = "\\s*Creation Date:\\s*[^\\n]+";
    private final String ETIMEREG = "\\s*Updated Date:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern contactPattern = Pattern.compile(CONTACTREG);
    private Pattern orgPattern = Pattern.compile(ORGREG);
    private Pattern phonePattern = Pattern.compile(PHONEREG);
    private Pattern emailPattern = Pattern.compile(EMAILREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEREG);
    private Pattern utimePattern = Pattern.compile(ETIMEREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");

    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try {
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
            String contact = getFieldValue(getMatchField(contactPattern, whoisResponse), ":");
            whoisModel.setContacts(contact);
            String org = getFieldValue(getMatchField(orgPattern, whoisResponse), ":");
            whoisModel.setOrgnization(org);
            String phone = getFieldValue(getMatchField(phonePattern, whoisResponse), ":");
            whoisModel.setPhone(phone);
            String email = getFieldValue(getMatchField(emailPattern, whoisResponse), ":");
            whoisModel.setEmail(email);
            String ctime = getFieldValue(getMatchField(ctimePattern, whoisResponse), ":");
            String utime = getFieldValue(getMatchField(utimePattern, whoisResponse), ":");
            ctime = ctime.split("\\.")[0];
            utime = utime.split("\\.")[0];
            whoisModel.setCtime(simpleDateFormat.parse(ctime).getTime());
            whoisModel.setUtime(simpleDateFormat.parse(utime).getTime());
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
