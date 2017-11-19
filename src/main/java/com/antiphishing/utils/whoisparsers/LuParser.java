package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;
/**
 * Created by dell on 17-11-18.
 */

/**
 * % Access to RESTENA DNS-LU WHOIS information is provided to assist persons
 % in determining the content of a domain name registration record in the LU
 % registration database. The data in this record is provided by RESTENA DNS-LU
 % for information purposes only, and RESTENA DNS-LU does not guarantee its
 % accuracy. Compilation, repackaging, dissemination or other use of the
 % WHOIS database in its entirety, or of a substantial part thereof, is not
 % allowed without the prior written permission of RESTENA DNS-LU.
 %
 % By submitting a WHOIS query, you agree to abide by this policy. You acknowledge
 % that the use of the WHOIS database is regulated by the ACCEPTABLE USE POLICY
 % (http://www.dns.lu/en/support/domainname-availability/whois-gateway/), that you are aware of its
 % content, and that you accept its terms and conditions.
 %
 % You agree especially that you will use this data only for lawful purposes and
 % that you will not use this data to:
 % (1) allow, enable, or otherwise support the transmission of mass unsolicited,
 % commercial advertising or solicitations via e-mail (spam); or
 % (2) enable high volume, automated, electronic processes that apply to
 % RESTENA DNS-LU (or its systems).
 %
 % All rights reserved.
 %
 % WHOIS gouvernement.lu
 domainname:     gouvernement.lu
 domaintype:     ACTIVE
 nserver:        ns1.etat.lu
 nserver:        ns2.etat.lu
 ownertype:      ORGANISATION
 registered:     22/06/2015
 org-name:       Centre des Technologies de l'Information de l'Etat (CTIE)
 org-address:    PoBox 1111
 org-zipcode:    1011
 org-city:       Luxembourg
 org-country:    LU
 adm-name:       David Thomas
 adm-address:    Centre des technologies de l'information de l'Etat (CTIE)
 adm-address:    1, rue Mercier
 adm-zipcode:    1011
 adm-city:       Luxembourg
 adm-country:    LU
 adm-email:      renow.info@ctie.etat.lu
 tec-name:       Yves Asselborn
 tec-address:    Centre des technologies de l'information de l'Etat (CTIE)
 tec-address:    1, rue Mercier
 tec-zipcode:    1011
 tec-city:       Luxembourg
 tec-country:    LU
 tec-email:      cms@ctie.etat.lu
 registrar-name:         Fondation RESTENA
 registrar-email:        domreg@dns.lu
 registrar-url:          http://www.dns.lu
 registrar-country:      LU
 */
public class LuParser extends AParser{
    private LuParser(){}

    private static LuParser instance = null;

    public static LuParser getInstance(){
        if(instance == null){
            instance = new LuParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*domainname:\\s*[^\\n]+";
    private final String ORGREG = "\\s*org\\-name:\\s*[^\\n]+";
    private final String EMAILREG = "\\s*adm\\-email:\\s*[^\\n]+";
    private final String CTIMEREG = "\\s*registered:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern orgPattern = Pattern.compile(ORGREG);
    private Pattern emailPattern = Pattern.compile(EMAILREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("dd/MM/yyyy");

    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try {
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":").replaceAll("\\s+", "").replaceAll("name:", "");
            whoisModel.setDomain(domain);
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
            String org = getFieldValue(getMatchField(orgPattern, whoisResponse), ":");
            whoisModel.setOrgnization(org);
            String email = getFieldValue(getMatchField(emailPattern, whoisResponse), ":");
            whoisModel.setEmail(email);
            String ctime = getFieldValue(getMatchField(ctimePattern, whoisResponse), ":");
            whoisModel.setCtime(simpleDateFormat.parse(ctime).getTime());
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
