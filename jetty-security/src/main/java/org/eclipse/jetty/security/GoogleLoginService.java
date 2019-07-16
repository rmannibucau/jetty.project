package org.eclipse.jetty.security;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import javax.servlet.ServletRequest;

import org.eclipse.jetty.security.authentication.GoogleCredentials;
import org.eclipse.jetty.server.UserIdentity;
import org.eclipse.jetty.util.ajax.JSON;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.Logger;

public class GoogleLoginService implements LoginService
{
    private static final Logger LOG = Log.getLogger(GoogleLoginService.class);
    private static final String token_endpoint = "https://oauth2.googleapis.com/token";
    private static final String issuer = "https://accounts.google.com";

    private UserStore _userStore;
    private IdentityService identityService;

    private String clientId = "1051168419525-5nl60mkugb77p9j194mrh287p1e0ahfi.apps.googleusercontent.com";
    private String clientSecret = "XT_MIsSv_aUCGollauCaJY8S";
    private String redirectUri = "http://localhost:8080/authenticate";

    public GoogleLoginService(){} // TODO: remove

    public GoogleLoginService(String clientId, String clientSecret, String redirectUri)
    {
        // TODO: complete
    }

    @Override
    public String getName()
    {
        return this.getClass().getSimpleName();
    }

    @Override
    public UserIdentity login(String identifier, Object credentials, ServletRequest request)
    {
        if (!(credentials instanceof GoogleCredentials))
            return null;
        GoogleCredentials googleCredentials = (GoogleCredentials)credentials;

        Map<String, String> userInfo = googleCredentials.getUserInfo();
        if (userInfo != null)
        {
            // TODO: get UserIdentity
            String userId = userInfo.get("sub");








            return null;
        }

        String jsonWebToken = googleCredentials.getJsonWebToken();
        if (jsonWebToken != null)
        {
            // TODO: decode
            return null;
        }

        return null;
    }

    @Override
    public void logout(UserIdentity user)
    {

    }

    @Override
    public boolean validate(UserIdentity user)
    {
        LOG.warn("validating {}", user);
        return true;
    }

    @Override
    public IdentityService getIdentityService()
    {
        return identityService;
    }

    @Override
    public void setIdentityService(IdentityService service)
    {
        this.identityService = service;
    }

    protected GoogleUserPrincipal loadUserInfo(String userId)
    {
        UserIdentity id = _userStore.getUserIdentity(userId);
        if (id != null)
            return (GoogleUserPrincipal)id.getUserPrincipal();

        return null;
    }

    protected String[] loadRoleInfo(GoogleUserPrincipal user)
    {
        UserIdentity id = _userStore.getUserIdentity(user.getName());
        if (id == null)
            return null;

        Set<AbstractLoginService.RolePrincipal> roles = id.getSubject().getPrincipals(AbstractLoginService.RolePrincipal.class);
        if (roles == null)
            return null;

        List<String> list = roles.stream()
            .map(rolePrincipal -> rolePrincipal.getName())
            .collect(Collectors.toList());

        return list.toArray(new String[roles.size()]);
    }

    public static Map<String, String> decodeAndVerifyIdToken(String jwt) throws IOException
    {
        // TODO: in production this verification should be done locally with appropriate libraries
        // NOTE: it is not necessary to check signature if this comes directly from google (authorisation code flow)
        final String tokenInfoEndpoint = "https://oauth2.googleapis.com/tokeninfo";
        URL url = new URL(tokenInfoEndpoint+"?id_token="+jwt);
        InputStream content = (InputStream)url.getContent();
        return (Map)JSON.parse(new String(content.readAllBytes()));
    }

    public Map<String, String> getIdToken(String authCode) throws IOException
    {
        String urlParameters = "code=" + authCode +
            "&client_id=" + clientId +
            "&client_secret=" + clientSecret +
            "&redirect_uri=" + redirectUri +
            "&grant_type=authorization_code";
        byte[] payload = urlParameters.getBytes(StandardCharsets.UTF_8);

        URL url = new URL(token_endpoint);
        HttpURLConnection connection = (HttpURLConnection)url.openConnection();
        connection.setDoOutput(true);
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Host", issuer);
        connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        connection.setRequestProperty( "charset", "utf-8");

        try(DataOutputStream wr = new DataOutputStream(connection.getOutputStream()))
        {
            wr.write(payload);
        }

        InputStream content = (InputStream)connection.getContent();
        return (Map)JSON.parse(new String(content.readAllBytes()));
    }
}
