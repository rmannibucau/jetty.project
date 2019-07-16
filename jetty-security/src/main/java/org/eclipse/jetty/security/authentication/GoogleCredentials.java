package org.eclipse.jetty.security.authentication;

import java.util.Map;

public class GoogleCredentials
{
    private String authCode;
    private String jsonWebToken;
    private Map<String, String> userInfo;

    public GoogleCredentials()
    {
    }

    public String getAuthCode()
    {
        return authCode;
    }

    public String getJsonWebToken()
    {
        return jsonWebToken;
    }

    public Map<String, String> getUserInfo()
    {
        return userInfo;
    }

    public void setAuthCode(String authCode)
    {
        this.authCode = authCode;
    }

    public void setJsonWebToken(String jsonWebToken)
    {
        this.jsonWebToken = jsonWebToken;
    }

    public void setUserInfo(Map<String, String> userInfo)
    {
        this.userInfo = userInfo;
    }
}
