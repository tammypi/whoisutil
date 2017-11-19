package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.Locale;
import java.util.regex.Pattern;
/**
 * Created by dell on 2017/11/17.
 */
/**
 * % .be Whois Server 6.1
 %
 % The WHOIS service offered by DNS Belgium and the access to the records in the DNS Belgium
 % WHOIS database are provided for information purposes only. It allows
 % persons to check whether a specific domain name is still available or not
 % and to obtain information related to the registration records of
 % existing domain names.
 %
 % DNS Belgium cannot, under any circumstances, be held liable where the stored
 % information would prove to be incomplete or inaccurate in any sense.
 %
 % By submitting a query you agree not to use the information made available
 % to:
 %   - allow, enable or otherwise support the transmission of unsolicited,
 %     commercial advertising or other solicitations whether via email or otherwise;
 %   - target advertising in any possible way;
 %   - to cause nuisance in any possible way to the domain name holders by sending
 %     messages to them (whether by automated, electronic processes capable of
 %     enabling high volumes or other possible means).
 %
 % Without prejudice to the above, it is explicitly forbidden to extract, copy
 % and/or use or re-utilise in any form and by any means (electronically or
 % not) the whole or a quantitatively or qualitatively substantial part
 % of the contents of the WHOIS database without prior and explicit permission
 % by DNS Belgium, nor in any attempt thereof, to apply automated, electronic
 % processes to DNS Belgium (or its systems).
 %
 % You agree that any reproduction and/or transmission of data for commercial
 % purposes will always be considered as the extraction of a substantial
 % part of the content of the WHOIS database.
 %
 % By submitting the query you agree to abide by this policy and accept that
 % DNS Belgium can take measures to limit the use of its whois services in order to
 % protect the privacy of its registrants or the integrity of the database.
 %

 Domain:	febelfin.be
 Status:	NOT AVAILABLE
 Registered:	Tue Feb 25 2003

 Registrant:
 Not shown, please visit www.dnsbelgium.be for webbased whois.

 Registrar Technical Contacts:

 Registrar:
 Name:	 SPEEDPACKET
 Website: http://www.flexin.be

 Nameservers:
 ns1.belio.be
 ns2.belio.be

 Keys:
 keyTag:25660 flags:KSK protocol:3 algorithm:RSA-SHA256 pubKey:AwEAAb1MeMjqsinIVEgu/ElrJi2QxV0Y3Ko9de6B8BLQB4uodsvtsfqXB5rMUv+54mkboKdeFiZoKbewfys2/4qiWDwSIaSswoiciPw//FW1IetS0mrJr7Rp+kWUNHnrY189CmyBJhcwlIV4Q64HVMEg33SUMGT7GGEk6nSHqrY8Hhzb6NQZ5VwUHRWlzTdyXkwqCtk2OZ+3fTVswB2HwsXmk5sEQE/AwKGbDNWCgXvZeySbp5O4KPkSiZbVdzc5+wqVqbIo1XS/C+TlG3CR2PxGp7hOV4vLq20bVmDUEx/6kPzkaaDhuffybjgw5PZIv/qI031dPEfCVREr2WALZ2EnJj8=

 Flags:

 Please visit www.dnsbelgium.be for more info.
 */
public class BeParser extends AParser{
    private BeParser(){}

    private static BeParser instance = null;

    public static BeParser getInstance(){
        if(instance == null){
            instance = new BeParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*Domain:\\s*[^\\n]+";
    private final String CTIMEREG = "\\s*Registered:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("EEE MMM dd yyyy", Locale.ENGLISH);

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try{
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
            String ctime = getFieldValue(getMatchField(ctimePattern, whoisResponse), ":");
            whoisModel.setCtime(simpleDateFormat.parse(ctime).getTime());
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
