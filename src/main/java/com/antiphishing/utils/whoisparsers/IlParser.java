package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;
/**
 * Created by dell on 2017/11/17.
 */
/**
 * % The data in the WHOIS database of the .il registry is provided
 % by ISOC-IL for information purposes, and to assist persons in
 % obtaining information about or related to a domain name
 % registration record. ISOC-IL does not guarantee its accuracy.
 % By submitting a WHOIS query, you agree that you will use this
 % Data only for lawful purposes and that, under no circumstances
 % will you use this Data to: (1) allow, enable, or otherwise
 % support the transmission of mass unsolicited, commercial
 % advertising or solicitations via e-mail (spam);
 % or  (2) enable high volume, automated, electronic processes that
 % apply to ISOC-IL (or its systems).
 % ISOC-IL reserves the right to modify these terms at any time.
 % By submitting this query, you agree to abide by this policy.

 query:        israelpost.co.il

 reg-name:     israelpost
 domain:       israelpost.co.il

 descr:        michal kerem
 descr:        217 jaffa st.
 descr:        Jerusalem
 descr:        12345
 descr:        Israel
 phone:        +972 2 6295094
 e-mail:       ipa.security10 AT gmail.com
 admin-c:      DT-YN1643-IL
 tech-c:       DT-GP6265-IL
 zone-c:       DT-YN1644-IL
 nserver:      ns1.bezeqint.net
 nserver:      ns2.bezeqint.net
 nserver:      ns3.bezeqint.net
 validity:     08-01-2018
 DNSSEC:       unsigned
 status:       Transfer Locked
 changed:      domain-registrar AT isoc.org.il 20060108 (Assigned)
 changed:      domain-registrar AT isoc.org.il 20060209 (Changed)
 changed:      domain-registrar AT isoc.org.il 20070809 (Transferred)
 changed:      domain-registrar AT isoc.org.il 20070809 (Changed)
 changed:      domain-registrar AT isoc.org.il 20131119 (Changed)
 changed:      domain-registrar AT isoc.org.il 20131119 (Changed)
 changed:      domain-registrar AT isoc.org.il 20131119 (Changed)
 changed:      domain-registrar AT isoc.org.il 20131208 (Changed)
 changed:      domain-registrar AT isoc.org.il 20160418 (Changed)
 changed:      domain-registrar AT isoc.org.il 20160418 (Changed)
 changed:      domain-registrar AT isoc.org.il 20160418 (Changed)
 changed:      domain-registrar AT isoc.org.il 20160418 (Changed)
 changed:      domain-registrar AT isoc.org.il 20160418 (Changed)
 changed:      domain-registrar AT isoc.org.il 20160418 (Changed)

 person:       YYariv Negriariv Negri
 address:      Israel Post Ltd.
 address:      217 jaffa st.
 address:      Jerusalem -
 address:      91999
 address:      Israel
 phone:        +972 76 8875094
 e-mail:       yarivn AT postil.com
 nic-hdl:      DT-YN1643-IL
 changed:      Managing Registrar 20160418

 person:       Gilad Pomerantz
 address:      ISRAEL POST COMPANY LTD
 address:      217 jaffa st.
 address:      Jerusalem
 address:      91999
 address:      Israel
 phone:        +972 54 2888875
 e-mail:       pumi AT postil.com
 nic-hdl:      DT-GP6265-IL
 changed:      Managing Registrar 20131119

 person:       Yariv Negri
 address:      Israel Post
 address:      217 jaffa st.
 address:      Jerusalem
 address:      91999
 address:      Israel
 phone:        +972 76 8875094
 e-mail:       yarivn AT postil.com
 nic-hdl:      DT-YN1644-IL
 changed:      Managing Registrar 20160418

 registrar name: Domain The Net Technologies Ltd
 registrar info: http://www.domainthenet.com

 % Rights to the data above are restricted by copyright.
 */
public class IlParser extends AParser{
    private IlParser(){}

    private static IlParser instance = null;

    public static IlParser getInstance(){
        if(instance == null){
            instance = new IlParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*domain:\\s*[^\\n]+";
    private final String CONTACTSREG = "\\s*reg\\-name:\\s*[^\\n]+";
    private final String EMAILREG = "\\s*e\\-mail:\\s*[^\\n]+";
    private final String PHONEREG = "\\s*phone:\\s*[^\\n]+";
    private final String CTIMEREG = "\\s*changed:      domain\\-registrar AT isoc\\.org\\.il [0-9]+ \\(Assigned\\)\\n";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern contactsPattern = Pattern.compile(CONTACTSREG);
    private Pattern emailPattern = Pattern.compile(EMAILREG);
    private Pattern phonePattern = Pattern.compile(PHONEREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyyMMdd");

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try {
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
            String contacts = getFieldValue(getMatchField(contactsPattern, whoisResponse), ":");
            whoisModel.setContacts(contacts);
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
            String email = getFieldValue(getMatchField(emailPattern, whoisResponse), ":");
            whoisModel.setEmail(email);
            String phone = getFieldValue(getMatchField(phonePattern, whoisResponse), ":");
            whoisModel.setPhone(phone);
            String ctime = getMatchField(ctimePattern, whoisResponse);
            ctime = ctime.replaceAll("[\\s]+", " ").split(" ")[5];
            whoisModel.setCtime(simpleDateFormat.parse(ctime).getTime());
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
