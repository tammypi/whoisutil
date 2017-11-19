package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;
/**
 * Created by dell on 2017/11/17.
 */
/**
 * Disclaimer: VeriSign, Inc. makes every effort to maintain the
 completeness and accuracy of the Whois data, but cannot guarantee
 that the results are error-free. Therefore, any data provided
 through the Whois service are on an as is basis without any
 warranties.
 BY USING THE WHOIS SERVICE AND THE DATA CONTAINED
 HEREIN OR IN ANY REPORT GENERATED WITH RESPECT THERETO, IT IS
 ACCEPTED THAT VERISIGN, INC. IS NOT LIABLE FOR
 ANY DAMAGES OF ANY KIND ARISING OUT OF, OR IN CONNECTION WITH, THE
 REPORT OR THE INFORMATION PROVIDED BY THE WHOIS SERVICE, NOR
 OMISSIONS OR MISSING INFORMATION. THE RESULTS OF ANY WHOIS REPORT OR
 INFORMATION PROVIDED BY THE WHOIS SERVICE CANNOT BE RELIED UPON IN
 CONTEMPLATION OF LEGAL PROCEEDINGS WITHOUT FURTHER VERIFICATION, NOR
 DO SUCH RESULTS CONSTITUTE A LEGAL OPINION. Acceptance of the
 results of the Whois constitutes acceptance of these terms,
 conditions and limitations. Whois data may be requested only for
 lawful purposes, in particular, to protect legal rights and
 obligations. Illegitimate uses of Whois data include, but are not
 limited to, unsolicited email, data mining, direct marketing or any
 other improper purpose. Any request made for Whois data will be
 documented by VeriSign, Inc. but will not be used for any commercial purpose whatsoever.

 ****

 Registry Domain ID: 4006448_DOMAIN_NAME-VRSN
 Domain Name: SOSUO.NAME
 Registrar: Name.com, Inc.
 Registrar IANA ID: 625
 Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited

 >>> Last update of whois database: 2017-11-17T01:57:28Z <<<

 For more information on Whois status codes, please visit https://icann.org/epp
 */
public class NameParser extends AParser{
    private NameParser(){}

    private static NameParser instance = null;

    public static NameParser getInstance(){
        if(instance == null){
            instance = new NameParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*Domain Name:\\s*[^\\n]+";
    private final String UTIMEREG = ">>> [^<]+ <<<";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern utimePattern = Pattern.compile(UTIMEREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try{
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
            String utime = getFieldValue(getMatchField(utimePattern, whoisResponse), ":");
            utime = utime.trim().replaceAll("<", "");
            whoisModel.setUtime(simpleDateFormat.parse(utime).getTime());
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
