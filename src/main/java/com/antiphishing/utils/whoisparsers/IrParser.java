package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;
/**
 * Created by dell on 2017/11/14.
 */
/**
 * % This is the IRNIC Whois server v1.6.2.
 % Available on web at http://whois.nic.ir/
 % Find the terms and conditions of use on http://www.nic.ir/
 %
 % This server uses UTF-8 as the encoding for requests and responses.

 % NOTE: This output has been filtered.

 % Information related to 'aaa.ir'


 domain:		aaa.ir
 ascii:		aaa.ir
 remarks:	(Domain Holder) Afshin Aslani
 remarks:	(Domain Holder Address) No. 121, Iran Zamin St., Shahrake Gharb,, Tehran, Tehran, IR
 holder-c:	aa268-irnic
 admin-c:	aa268-irnic
 tech-c:		na88-irnic
 nserver:	ns1.netswebs.net
 last-updated:	2017-05-14
 expire-date:	2018-01-11
 source:		IRNIC # Filtered

 nic-hdl:	aa268-irnic
 person:		Afshin Aslani
 e-mail:		aslani.afshin@gmail.com
 address:	No. 121, Iran Zamin St., Shahrake Gharb,, Tehran, Tehran, IR
 phone:		+98 912 327 3541
 source:		IRNIC # Filtered

 nic-hdl:	na88-irnic
 org:		Mohandesie Nano Samaneh (Nano)
 e-mail:		domains@nano.co.ir
 source:		IRNIC # Filtered
 */
public class IrParser extends AParser{
    private IrParser(){}
    private static IrParser instance = null;

    public static IrParser getInstance(){
        if(instance == null){
            instance = new IrParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*domain:\\s*[^\\n]+";
    private final String CONTACTREG = "\\s*person:\\s*[^\\n]+";
    private final String ORGNIZATIONREG = "\\s*org:\\s*[^\\n]+";
    private final String UTIMEREG = "\\s*last-updated:\\s*[^\\n]+";
    private final String EMAILREG = "\\s*e-mail:\\s*[^\\n]+";
    private final String PHONEREG = "\\s*phone:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern contactPattern = Pattern.compile(CONTACTREG);
    private Pattern orgnizationPattern = Pattern.compile(ORGNIZATIONREG);
    private Pattern utimePattern = Pattern.compile(UTIMEREG);
    private Pattern emailPattern = Pattern.compile(EMAILREG);
    private Pattern phonePattern = Pattern.compile(PHONEREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd");

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
     WhoisModel whoisModel = new WhoisModel();
     try{
       String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
       whoisModel.setDomain(domain);
       String contacts = getFieldValue(getMatchField(contactPattern, whoisResponse), ":");
       whoisModel.setContacts(contacts);
       String orgnization = getFieldValue(getMatchField(orgnizationPattern, whoisResponse), ":");
       whoisModel.setOrgnization(orgnization);
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
