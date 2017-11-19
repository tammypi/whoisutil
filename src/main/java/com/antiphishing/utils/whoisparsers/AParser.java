package com.antiphishing.utils.whoisparsers;
import com.antiphishing.models.WhoisModel;
import java.io.Serializable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by dell on 2017/11/14.
 */
public abstract class AParser implements Serializable{
    public abstract WhoisModel parseWhois(String whoisResponse);

    protected String getMatchField(Pattern pattern, String source) {
        Matcher matcher = pattern.matcher(source);
        if(matcher.find()) {
            return getMatchString(matcher, source);
        }
        return null;
    }

    protected String getFieldValue(String source, String delimiter) {
        if(source == null || source.isEmpty()) {
            return "";
        }
        return source.split(delimiter, 2)[1].trim();
    }

    protected String getMatchString(Matcher matcher, String source) {
        return source.substring(matcher.start(), matcher.end());
    }
}
