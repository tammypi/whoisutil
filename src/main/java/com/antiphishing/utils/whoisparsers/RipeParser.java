package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
/**
 * Created by dell on 2017/11/15.
 */

/**
 * % This is the RIPE Database query service.
 % The objects are in RPSL format.
 %
 % The RIPE Database is subject to Terms and Conditions.
 % See http://www.ripe.net/db/support/db-terms-conditions.pdf

 % Note: this output has been filtered.
 %       To receive output for a database update, use the "-B" flag.

 %ERROR:101: no entries found
 %
 % No entries found in source RIPE.

 % This query was served by the RIPE Database Query Service version 1.90 (WAGYU)
 */
public class RipeParser extends AParser{
    private RipeParser(){}

    private static RipeParser instance = null;

    public static RipeParser getInstance(){
        if(instance == null){
            instance = new RipeParser();
        }
        return instance;
    }

    @Override
    public WhoisModel parseWhois(String whoisResponse) {
        WhoisModel whoisModel = new WhoisModel();
        try{
            //cannot find entries ? why ?
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return whoisModel;
    }
}
