package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;
/**
 * Created by dell on 17-11-19.
 */
/**
 * Domain Name: TEST.ORG
 Registry Domain ID: D380528-LROR
 Registrar WHOIS Server: whois.psi-usa.info
 Registrar URL: http://www.psi-usa.info
 Updated Date: 2017-07-27T01:46:13Z
 Creation Date: 1997-07-27T04:00:00Z
 Registry Expiry Date: 2018-07-26T04:00:00Z
 Registrar Registration Expiration Date:
 Registrar: PSI-USA, Inc. dba Domain Robot
 Registrar IANA ID: 151
 Registrar Abuse Contact Email: domain-abuse@psi-usa.info
 Registrar Abuse Contact Phone: +49.94159559482
 Reseller:
 Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
 Registry Registrant ID: C3438367-LROR
 Registrant Name: Peter Maisel
 Registrant Organization: TMT Teleservice GmbH & Co.KG
 Registrant Street: Nuernberger Strasse 42
 Registrant City: Bayreuth
 Registrant State/Province: Bayern
 Registrant Postal Code: 95448
 Registrant Country: DE
 Registrant Phone: +49.9215072000
 Registrant Phone Ext:
 Registrant Fax: +49.921507200299
 Registrant Fax Ext:
 Registrant Email: maisel_nospam_@tmt.de
 Registry Admin ID: C3438367-LROR
 Admin Name: Peter Maisel
 Admin Organization: TMT Teleservice GmbH & Co.KG
 Admin Street: Nuernberger Strasse 42
 Admin City: Bayreuth
 Admin State/Province: Bayern
 Admin Postal Code: 95448
 Admin Country: DE
 Admin Phone: +49.9215072000
 Admin Phone Ext:
 Admin Fax: +49.921507200299
 Admin Fax Ext:
 Admin Email: maisel_nospam_@tmt.de
 Registry Tech ID: C95450806-LROR
 Tech Name: TMT Hostmaster
 Tech Organization: TMT GmbH & Co.KG
 Tech Street: Nuernberger Strasse 42
 Tech City: Bayreuth
 Tech State/Province: Bayern
 Tech Postal Code: 95448
 Tech Country: DE
 Tech Phone: +49.9215072000
 Tech Phone Ext:
 Tech Fax: +49.921507200299
 Tech Fax Ext:
 Tech Email: domadm_nospam_@tmt.de
 Name Server: NS0.TMT.DE
 Name Server: NS4.TMT.DE
 Name Server: NS3.TMT.DE
 Name Server: NS2.TMT.DE
 Name Server: NS1.TMT.DE
 DNSSEC: unsigned
 URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
 >>> Last update of WHOIS database: 2017-11-19T11:43:38Z <<<
 */
public class OrgParser extends AParser{
    private OrgParser(){}

    private static OrgParser instance = null;

    public static OrgParser getInstance(){
        if(instance == null){
            instance = new OrgParser();
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
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");

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
            whoisModel.setCtime(simpleDateFormat.parse(ctime).getTime());
            whoisModel.setUtime(simpleDateFormat.parse(utime).getTime());
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
