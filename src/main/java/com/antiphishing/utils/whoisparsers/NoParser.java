package com.antiphishing.utils.whoisparsers;

import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;

/**
 * Created by dell on 2017/11/15.
 */

/**
 * % Kopibeskyttet, se http://www.norid.no/domenenavnbaser/whois/kopirett.html
 % Rights restricted by copyright. See http://www.norid.no/domenenavnbaser/whois/kopirett.en.html

 Domain Information

 NORID Handle...............: AAA42D-NORID
 Domain Name................: aaa.no
 Domain Holder Handle.......: AAI10O-NORID
 Registrar Handle...........: REG812-NORID
 Legal-c Handle.............: AA3488P-NORID
 Tech-c Handle..............: HM1278P-NORID
 Name Server Handle.........: NSON12H-NORID
 Name Server Handle.........: NSON8H-NORID
 DNSSEC.....................: Signed
 DS Key Tag     1...........: 51535
 Algorithm      1...........: 8
 Digest Type    1...........: 2
 Digest         1...........: 86c2f6d5cfe9a70ad39d5951dd8e391de2a9505098598797acbf76a95bb8d58c

 Additional information:
 Created:         1999-11-15
 Last updated:    2017-11-15

 NORID Handle...............: AAI10O-NORID
 Type.......................: organization
 Name.......................: INFOTEK ARVID AAKRE
 Id Type....................: organization_number
 Id Number..................: 980957373
 Registrar Handle...........: REG812-NORID
 Post Address...............: Okstadbrinken 18
 Postal Code................: NO-7075
 Postal Area................: Tiller
 Country....................: NO
 Phone Number...............: +47.92619418
 Mobile Phone Number........: +47.92619418
 Fax Number.................: +47.92774418
 Email Address..............: arvid.aakre@ntnu.no

 Additional information:
 Created:         2010-10-01
 Last updated:    2011-02-09
 */
public class NoParser extends AParser{
    private NoParser(){}

    private static NoParser instance = null;

    public static NoParser getInstance(){
        if(instance == null){
            instance = new NoParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*Domain Name................:\\s*[^\\n]+";
    private final String CONTACTSREG = "\\sName.......................:\\s*[^\\n]+";
    private final String CTIMEREG = "\\s*Created:\\s*[^\\n]+";
    private final String UTIMEREG = "\\s*Last updated:\\s*[^\\n]+";
    private final String PHONEREG = "\\s*Phone Number...............:\\s*[^\\n]+";
    private final String EMAILREG = "\\s*Email Address..............:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern contactPattern = Pattern.compile(CONTACTSREG);
    private Pattern ctimePattern = Pattern.compile(CTIMEREG);
    private Pattern utimePattern = Pattern.compile(UTIMEREG);
    private Pattern phonePattern = Pattern.compile(PHONEREG);
    private Pattern emailPattern = Pattern.compile(EMAILREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd");

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try{
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
            String contacts = getFieldValue(getMatchField(contactPattern, whoisResponse), ":");
            whoisModel.setContacts(contacts);
            String ctime = getFieldValue(getMatchField(ctimePattern, whoisResponse), ":");
            whoisModel.setCtime(simpleDateFormat.parse(ctime.trim()).getTime());
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
