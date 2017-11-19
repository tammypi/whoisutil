package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;
/**
 * Created by dell on 2017/11/15.
 */
/**
 * % Copyright (c)2017 by NIC.AT (1)
 %
 % Restricted rights.
 %
 % Except  for  agreed Internet  operational  purposes, no  part  of this
 % information  may  be reproduced,  stored  in  a  retrieval  system, or
 % transmitted, in  any  form  or by  any means,  electronic, mechanical,
 % recording, or otherwise, without prior  permission of NIC.AT on behalf
 % of itself and/or the copyright  holders.  Any use of this  material to
 % target advertising  or similar activities is explicitly  forbidden and
 % can be prosecuted.
 %
 % It is furthermore strictly forbidden to use the Whois-Database in such
 % a  way  that  jeopardizes or  could jeopardize  the  stability  of the
 % technical  systems of  NIC.AT  under any circumstances. In particular,
 % this includes  any misuse  of the  Whois-Database and  any  use of the
 % Whois-Database which disturbs its operation.
 %
 % Should the  user violate  these points,  NIC.AT reserves  the right to
 % deactivate  the  Whois-Database   entirely  or  partly  for  the user.
 % Moreover,  the  user  shall be  held liable  for  any  and all  damage
 % arising from a violation of these points.

 domain:         stiegl.at
 registrant:     SZSG6865857-NICAT
 admin-c:        SZSG6865857-NICAT
 tech-c:         NG3184298-NICAT
 nserver:        ns1.netzpionier.at
 nserver:        ns2.netzpionier.at
 nserver:        ns3.netzpionier.at
 changed:        20100210 14:28:28
 source:         AT-DOM

 personname:
 organization:   Stieglbrauerei zu Salzburg GmbH
 street address: Kendlerstrasse 1
 postal code:    5017
 city:           Salzburg
 country:        Austria
 phone:          +4366283870
 fax-no:         +436628387112
 e-mail:         office@stiegl.at
 nic-hdl:        SZSG6865857-NICAT
 changed:        20100210 13:55:59
 source:         AT-DOM

 personname:     Technischer Support
 organization:   netzpionier GmbH
 street address: Kundratstrasse 6/2/3
 postal code:    1100
 city:           Wien
 country:        Austria
 phone:          +431268545300
 fax-no:         +431268545399
 e-mail:         support@netzpionier.at
 nic-hdl:        NG3184298-NICAT
 changed:        20100210 16:32:50
 source:         AT-DOM
 */
public class AtParser extends AParser{
    private AtParser(){}

    private static AtParser instance = null;

    public static AtParser getInstance(){
        if(instance == null){
            instance = new AtParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*domain:\\s*[^\\n]+";
    private final String CONTACTSREG = "\\sregistrant:\\s*[^\\n]+";
    private final String ORGNIZATIONREG = "\\s*organization:\\s*[^\\n]+";
    private final String UTIMEREG = "\\s*changed:\\s*[^\\n]+";
    private final String PHONEREG = "\\s*phone:\\s*[^\\n]+";
    private final String EMAILREG = "\\s*e-mail:\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern contactPattern = Pattern.compile(CONTACTSREG);
    private Pattern orgnizationPattern = Pattern.compile(ORGNIZATIONREG);
    private Pattern utimePattern = Pattern.compile(UTIMEREG);
    private Pattern phonePattern = Pattern.compile(PHONEREG);
    private Pattern emailPattern = Pattern.compile(EMAILREG);
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyyMMdd HH:mm:ss");

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
            String phone = getFieldValue(getMatchField(phonePattern, whoisResponse), ":");
            whoisModel.setPhone(phone);
            String email = getFieldValue(getMatchField(emailPattern, whoisResponse), ":");
            whoisModel.setEmail(email);
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
