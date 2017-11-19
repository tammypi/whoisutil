package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;
/**
 * Created by dell on 2017/11/16.
 */

/**
 * # Hello 119.97.214.138. Your session has been logged.
 #
 # Copyright (c) 2002 - 2017 by DK Hostmaster A/S
 #
 # Version: 2.0.2
 #
 # The data in the DK Whois database is provided by DK Hostmaster A/S
 # for information purposes only, and to assist persons in obtaining
 # information about or related to a domain name registration record.
 # We do not guarantee its accuracy. We will reserve the right to remove
 # access for entities abusing the data, without notice.
 #
 # Any use of this material to target advertising or similar activities
 # are explicitly forbidden and will be prosecuted. DK Hostmaster A/S
 # requests to be notified of any such activities or suspicions thereof.

 Domain:               test.dk
 DNS:                  test.dk
 Registered:           1998-01-20
 Expires:              2022-03-31
 Registration period:  5 years
 VID:                  no
 Dnssec:               Unsigned delegation
 Status:               Active

 Nameservers
 Hostname:             ns-auth03.kmd.dk
 Hostname:             ns-auth04.kmd.dk

 # Use option --show-handles to get handle information.
 # Whois HELP for more help.
 */
public class DkParser extends AParser{
    private DkParser(){}

    private static DkParser instance = null;

    public static DkParser getInstance(){
        if(instance == null){
            instance = new DkParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*Domain:\\s*[^\\n]+";
    private final String CTIMEREG = "\\s*Registered:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd");

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try {
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
