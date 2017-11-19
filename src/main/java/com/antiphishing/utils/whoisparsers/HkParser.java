package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;
/**
 * Created by dell on 17-11-18.
 */

/**
 * -------------------------------------------------------------------------------
 Whois server by HKIRC
 -------------------------------------------------------------------------------
 .hk top level Domain names can be registered via HKIRC-Accredited Registrars.
 Go to https://www.hkirc.hk/content.jsp?id=280 for details.
 -------------------------------------------------------------------------------



 Domain Name:  MTR.COM.HK
 Bundled Domain Name:  港鐵.公司.香港
 Domain Status: Active

 Contract Version:   Refer to registrar

 Registrar Name: CSC Corporate Domains, Inc.

 Registrar Contact Information: TLDSupport@cscinfo.com

 Reseller:




 Registrant Contact Information:

 Company English Name (It should be the same as the registered/corporation name on your Business Register Certificate or relevant documents): MTR CORPORATION LIMITED
 Company Chinese name:  香港鐵路有限公司
 Address: MTR HEADQUARTERS BUILDING, TELFORD PLAZA, KOWLOON BAY, KOWLOON, HONG KONG
 Country: HK
 Email: dnsadmin@mtr.com.hk
 Domain Name Commencement Date: 25-10-1995
 Expiry Date: 01-10-2018
 Re-registration Status:  Complete



 Administrative Contact Information:

 Given name: DOMAIN
 Family name: ADMINISTRATOR
 Company name: MTR CORPORATION LIMITED
 Address: MTR HEADQUARTERS BUILDING, TELFORD PLAZA, KOWLOON BAY
 Country: HK
 Phone: +852-29932598
 Fax: +852-29937702
 Email: dnsadmin@mtr.com.hk
 Account Name: HK4375879T




 Technical Contact Information:

 Family name: ADMINISTRATOR
 Company name: MTR CORPORATION LIMITED
 Address: MTR HEADQUARTERS BUILDING, TELFORD PLAZA, KOWLOON BAY
 Country: HK
 Phone: +852-29932598
 Fax: +852-29937702
 Email: dnsadmin@mtr.com.hk




 Name Servers Information:

 A1-227.AKAM.NET
 A11-64.AKAM.NET
 A14-65.AKAM.NET
 A4-66.AKAM.NET
 A5-67.AKAM.NET
 A6-64.AKAM.NET



 Status Information:

 Domain Prohibit Status: The domain is protected by .HK Lock Service.

 DNSSEC: unsigned



 -------------------------------------------------------------------------------
 The Registry contains ONLY .com.hk, .net.hk, .edu.hk, .org.hk,
 .gov.hk, idv.hk. and .hk $domains.
 -------------------------------------------------------------------------------

 WHOIS Terms of Use
 By using this WHOIS search enquiry service you agree to these terms of use.
 The data in HKDNR's WHOIS search engine is for information purposes only and HKDNR does not guarantee the accuracy of the data. The data is provided to assist people to obtain information about the registration record of domain names registered by HKDNR. You agree to use the data for lawful purposes only.

 You are not authorised to use high-volume, electronic or automated processes to access, query or harvest data from this WHOIS search enquiry service.

 You agree that you will not and will not allow anyone else to:

 a.    use the data for mass unsolicited commercial advertising of any sort via any medium including telephone, email or fax; or

 b.    enable high volume, automated or electronic processes that apply to HKDNR or its computer systems including the WHOIS search enquiry service; or

 c.    without the prior written consent of HKDNR compile, repackage, disseminate, disclose to any third party or use the data for a purpose other than obtaining information about a domain name registration record; or

 d.    use such data to derive an economic benefit for yourself.
 */
public class HkParser extends AParser{
    private HkParser(){}

    private static HkParser instance = null;

    public static HkParser getInstance(){
        if(instance == null){
            instance = new HkParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*Domain Name:\\s*[^\\n]+";
    private final String ORGREG = "\\s*Company Chinese name:\\s*[^\\n]+";
    private final String EMAILREG = "\\s*Email:\\s*[^\\n]+";
    private final String PHONEREG = "\\s*Phone:\\s*[^\\n]+";
    private final String CTIMEREG = "\\s*Domain Name Commencement Date:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern orgPattern = Pattern.compile(ORGREG);
    private Pattern emailPattern = Pattern.compile(EMAILREG);
    private Pattern phonePattern = Pattern.compile(PHONEREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("dd-MM-yyyy");

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
            String phone = getFieldValue(getMatchField(phonePattern, whoisResponse), ":");
            whoisModel.setPhone(phone);
            String ctime = getFieldValue(getMatchField(ctimePattern, whoisResponse), ":");
            whoisModel.setCtime(simpleDateFormat.parse(ctime).getTime());
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
