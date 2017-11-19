package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.util.regex.Pattern;
/**
 * Created by dell on 2017/11/15.
 */

/**
 * % Terms of Use
 %
 % By submitting a WHOIS query you are entering into an agreement with Domain
 % Name Commission Ltd on the following terms and conditions, and subject to
 % all relevant .nz Policies and procedures as found at https://dnc.org.nz/.
 %
 % It is prohibited to:
 % - Send high volume WHOIS queries with the effect of downloading part of or
 %   all of the .nz Register or collecting register data or records;
 % - Access the .nz Register in bulk through the WHOIS service (ie. where a
 %   user is able to access WHOIS data other than by sending individual queries
 %   to the database);
 % - Use WHOIS data to allow, enable, or otherwise support mass unsolicited
 %   commercial advertising, or mass solicitations to registrants or to
 %   undertake market research via direct mail, electronic mail, SMS, telephone
 %   or any other medium;
 % - Use WHOIS data in contravention of any applicable data and privacy laws,
 %   including the Unsolicited Electronic Messages Act 2007;
 % - Store or compile WHOIS data to build up a secondary register of
 %   information;
 % - Publish historical or non-current versions of WHOIS data; and
 % - Publish any WHOIS data in bulk.
 %
 % Copyright Domain Name Commission Limited (a company wholly-owned by Internet
 % New Zealand Incorporated) which may enforce its rights against any person or
 % entity that undertakes any prohibited activity without its written
 % permission.
 %
 % The WHOIS service is provided by NZRS Limited.
 %
 version: 8.0
 query_datetime: 2017-11-15T15:28:58+13:00
 domain_name: internetnz.nz
 query_status: 440 Request Denied
 %
 */
public class NzParser extends AParser{
    private NzParser(){}

    private static NzParser instance = null;

    public static NzParser getInstance(){
        if(instance == null){
            instance = new NzParser();
        }
        return instance;
    }

    private final String DOMAINREG = "domain_name:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try{
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
