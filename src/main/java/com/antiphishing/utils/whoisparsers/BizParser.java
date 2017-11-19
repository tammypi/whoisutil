package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;
/**
 * Created by dell on 2017/11/14.
 */

/**
 * Domain Name: aaa.biz
 Registry Domain ID: D2847323-BIZ
 Registrar WHOIS Server:
 Registrar URL: www.networksolutions.com
 Updated Date: 2017-11-05T07:15:54Z
 Creation Date: 2002-03-27T22:50:05Z
 Registry Expiry Date: 2019-03-26T23:59:59Z
 Registrar: Network Solutions, LLC
 Registrar IANA ID: 2
 Registrar Abuse Contact Email: abuse@web.com
 Registrar Abuse Contact Phone: +1.8003337680
 Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
 Registry Registrant ID: C58364675-BIZ
 Registrant Name: Perfect Privacy, LLC
 Registrant Organization:
 Registrant Street: 12808 Gran Bay Parkway West
 Registrant Street: care of Network Solutions
 Registrant Street:
 Registrant City: Jacksonville
 Registrant State/Province: FL
 Registrant Postal Code: 32258
 Registrant Country: US
 Registrant Phone: +1.5707088780
 Registrant Phone Ext:
 Registrant Fax:
 Registrant Fax Ext:
 Registrant Email: tn6c24m57qg@networksolutionsprivateregistration.com
 Registry Admin ID: C58364675-BIZ
 Admin Name: Perfect Privacy, LLC
 Admin Organization:
 Admin Street: 12808 Gran Bay Parkway West
 Admin Street: care of Network Solutions
 Admin Street:
 Admin City: Jacksonville
 Admin State/Province: FL
 Admin Postal Code: 32258
 Admin Country: US
 Admin Phone: +1.5707088780
 Admin Phone Ext:
 Admin Fax:
 Admin Fax Ext:
 Admin Email: tn6c24m57qg@networksolutionsprivateregistration.com
 Registry Tech ID: C58364675-BIZ
 Tech Name: Perfect Privacy, LLC
 Tech Organization:
 Tech Street: 12808 Gran Bay Parkway West
 Tech Street: care of Network Solutions
 Tech Street:
 Tech City: Jacksonville
 Tech State/Province: FL
 Tech Postal Code: 32258
 Tech Country: US
 Tech Phone: +1.5707088780
 Tech Phone Ext:
 Tech Fax:
 Tech Fax Ext:
 Tech Email: tn6c24m57qg@networksolutionsprivateregistration.com
 Name Server: waldo.national.aaa.com
 Name Server: ns-west.cerf.net
 DNSSEC: unsigned
 URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
 >>> Last update of WHOIS database: 2017-11-14T10:18:50Z <<<

 For more information on Whois status codes, please visit https://icann.org/epp
 */
public class BizParser extends AParser{
    private BizParser(){}
    private static BizParser instance = null;

    public static BizParser getInstance(){
        if(instance == null){
            instance = new BizParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*Domain\\sName:\\s*[^\\n]+";
    private final String CONTACTSREG = "\\sRegistrant Name:\\s*[^\\n]+";
    private final String ORGNIZATIONREG = "\\s*Registrant Organization:\\s*[^\\n]+";
    private final String CTIMEREG = "\\s*Creation Date:\\s*[^\\n]+";
    private final String UTIMEREG = "\\s*Updated Date:\\s*[^\\n]+";
    private final String PHONEREG = "\\s*Tech Phone:\\s*[^\\n]+";
    private final String EMAILREG = "\\s*Tech Email:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern contactPattern = Pattern.compile(CONTACTSREG);
    private Pattern orgnizationPattern = Pattern.compile(ORGNIZATIONREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEREG);
    private Pattern utimePattern = Pattern.compile(UTIMEREG);
    private Pattern phonePattern = Pattern.compile(PHONEREG);
    private Pattern emailPattern = Pattern.compile(EMAILREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try{
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
            String contacts = getFieldValue(getMatchField(contactPattern, whoisResponse), "Name:");
            whoisModel.setContacts(contacts);
            String orgnization = getFieldValue(getMatchField(orgnizationPattern, whoisResponse), ":");
            whoisModel.setOrgnization(orgnization);
            String ctime = getFieldValue(getMatchField(ctimePattern, whoisResponse), ":");
            whoisModel.setCtime(simpleDateFormat.parse(ctime.trim()).getTime());
            String utime = getFieldValue(getMatchField(utimePattern, whoisResponse), ":");
            whoisModel.setUtime(simpleDateFormat.parse(utime.trim()).getTime());
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
            String phone = getFieldValue(getMatchField(phonePattern, whoisResponse), ":");
            whoisModel.setPhone(phone);
            String email = getFieldValue(getMatchField(emailPattern, whoisResponse), ":");
            whoisModel.setEmail(email);
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
