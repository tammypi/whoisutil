package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import com.antiphishing.utils.IpUtil;

import java.util.regex.Pattern;
/**
 * Created by dell on 2017/11/15.
 */

/**
 * Domain name: aaa.nl
 Status:      active

 Registrar:
 Netbasics Holding B.V.
 Plantagelaan 59
 3772MB BARNEVELD
 Netherlands

 Abuse Contact:

 DNSSEC:      no

 Domain nameservers:
 janus.netbasics.nl
 minerva.netbasics.nl

 Record maintained by: NL Domain Registry

 Copyright notice
 No part of this publication may be reproduced, published, stored in a
 retrieval system, or transmitted, in any form or by any means,
 electronic, mechanical, recording, or otherwise, without prior
 permission of the Foundation for Internet Domain Registration in the
 Netherlands (SIDN).
 These restrictions apply equally to registrars, except in that
 reproductions and publications are permitted insofar as they are
 reasonable, necessary and solely in the context of the registration
 activities referred to in the General Terms and Conditions for .nl
 Registrars.
 Any use of this material for advertising, targeting commercial offers or
 similar activities is explicitly forbidden and liable to result in legal
 action. Anyone who is aware or suspects that such activities are taking
 place is asked to inform the Foundation for Internet Domain Registration
 in the Netherlands.
 (c) The Foundation for Internet Domain Registration in the Netherlands
 (SIDN) Dutch Copyright Act, protection of authors' rights (Section 10,
 subsection 1, clause 1).
 */
public class NlParser extends AParser{
    private NlParser(){}

    private static NlParser instance = null;

    public static NlParser getInstance(){
        if(instance == null){
            instance = new NlParser();
        }
        return instance;
    }

    private final String DOMAINREG = "\\s*Domain name:\\s*[^\\n]+";
    private final String CONTACTSREG = "\\sRegistrar:\\r\\n\\s*[^\\n]+";
    private Pattern domainPattern = Pattern.compile(DOMAINREG);
    private Pattern contactPattern = Pattern.compile(CONTACTSREG);

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try{
            String domain = getFieldValue(getMatchField(domainPattern, whoisResponse), ":");
            whoisModel.setDomain(domain);
            String contacts = getFieldValue(getMatchField(contactPattern, whoisResponse), ":");
            whoisModel.setContacts(contacts);
            whoisModel.setIp(IpUtil.getIpByDomain(domain));
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
