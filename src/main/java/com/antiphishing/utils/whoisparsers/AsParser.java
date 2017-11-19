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
 * Domain:
 aaa.as

 Domain Status:
 Active


 Registrant:
 Jeremy Howard


 Registrar:
 gdns (http://www.nic.as)

 Relevant dates:
 Registered on 17th August 2010
 Registry fee due on 17th August each year

 Registration status:
 Registered until cancelled

 Name servers:
 ns1.messagingengine.com
 ns2.messagingengine.com


 WHOIS lookup made on Wed, 15 Nov 2017 at 1:37:38 UTC

 This WHOIS information is provided for free by CIDR, operator of
 the backend registry for domain names ending in GG, JE, and AS.

 Copyright (c) and database right AS Domain Registry 1997 - 2017.

 You may not access this WHOIS server or use any data from it except
 as permitted by our Terms and Conditions which are published
 at http://www.channelisles.net/legal/whoisterms

 They include restrictions and prohibitions on

 - using or re-using the data for advertising;
 - using or re-using the service for commercial purposes without a licence;
 - repackaging, recompilation, redistribution or reuse;
 - obscuring, removing or hiding any or all of this notice;
 - exceeding query rate or volume limits.

 The data is provided on an 'as-is' basis and may lag behind the
 register. Access may be withdrawn or restricted at any time.
 */
public class AsParser extends AParser{
    private AsParser(){}

    private static AsParser asParser = null;

    public static AsParser getInstance(){
        if(asParser == null){
            asParser = new AsParser();
        }
        return asParser;
    }

    private final String DOMAINREG = "\\s*Domain:\\n\\s*[^\\n]+";
    private final String CONTACTSREG = "\\sRegistrant:\\n\\s*[^\\n]+";
    private final String CTIMEREG = "\\sRegistered on\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern contactPattern = Pattern.compile(CONTACTSREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("dd'th' MMM yyyy", Locale.ENGLISH);

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try{
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
            String contacts = getFieldValue(getMatchField(contactPattern, whoisResponse), ":");
            whoisModel.setContacts(contacts);
            String ctime = getFieldValue(getMatchField(ctimePattern, whoisResponse), "Registered on ");
            whoisModel.setCtime(simpleDateFormat.parse(ctime).getTime());
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
