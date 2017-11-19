package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;
/**
 * Created by dell on 2017/11/17.
 */
/**
 * Domain Name: TEST.SH
 Registry Domain ID: D503300000040519692-LRMS
 Registrar WHOIS Server: whois.rrpproxy.net
 Registrar URL: http://www.key-systems.net
 Updated Date: 2017-09-07T11:13:47Z
 Creation Date: 2007-09-11T04:49:24Z
 Registry Expiry Date: 2018-09-11T04:49:24Z
 Registrar Registration Expiration Date:
 Registrar: Key-Systems GmbH
 Registrar IANA ID: 269
 Registrar Abuse Contact Email: abuse@key-systems.net
 Registrar Abuse Contact Phone: +49.68949396850
 Reseller:
 Domain Status: ok https://icann.org/epp#ok
 Name Server: NS1.V4DNS.JP
 Name Server: NS2.V4DNS.JP
 DNSSEC: unsigned
 URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
 >>> Last update of WHOIS database: 2017-11-17T08:03:06Z <<<

 For more information on Whois status codes, please visit https://icann.org/epp

 Access to WHOIS information provided by Internet Computer Bureau Ltd. ("ICB") is provided to assist persons in determining the contents of a domain name registration record in the ICB registry database. The data in this record is provided by ICB for informational purposes only, and ICB does not guarantee its accuracy. This service is intended only for query-based access. You agree that you will use this data only for lawful purposes and that, under no circumstances will you use this data to(i) allow, enable, or otherwise support the transmission by e-mail, telephone, facsimile or other electronic means of mass, unsolicited, commercial advertising or solicitations to entities other than the data recipient's own existing customers; or (ii) enable high volume, automated, electronic processes that send queries or data to the systems of Registry Operator, a Registrar, or ICB or its services providers except as reasonably necessary to register domain names or modify existing registrations. UK privacy laws limit the scope of information permitted for certain public access.  Therefore, concerns regarding abusive use of domain registrations in the ICB registry should be directed to either (a) the Registrar of Record as indicated in the WHOIS output, or (b) the ICB anti-abuse department at abuse@icbregistry.info.

 All rights reserved. ICB reserves the right to modify these terms at any time. By submitting this query, you agree to abide by these policies.
 */
public class ShParser extends AParser{
    private ShParser(){}

    private static ShParser instance = null;

    public static ShParser getInstance(){
        if(instance == null){
            instance = new ShParser();
        }
        return instance;
    }


    private final String DOMAINREG = "\\s*Domain Name:\\s*[^\\n]+";
    private final String CTIMEREG = "\\s*Creation Date:\\s*[^\\n]+";
    private final String UTIMEREG = "\\s*Updated Date:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEREG);
    private Pattern utimePattern = Pattern.compile(UTIMEREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try{
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
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
