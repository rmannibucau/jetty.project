package org.eclipse.jetty.security.authentication;

import java.math.BigInteger;
import java.security.SecureRandom;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http.HttpStatus;
import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.security.ServerAuthException;
import org.eclipse.jetty.server.Authentication;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.UserIdentity;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.Logger;
import org.eclipse.jetty.util.security.Constraint;

public class GoogleAuthenticator extends LoginAuthenticator
{
    private static final Logger LOG = Log.getLogger(GoogleAuthenticator.class);


    private static final String CSRF_TOKEN_ATTRIBUTE = "CSRF_TOKEN_ATTRIBUTE";


    // TODO: make configurable (init params of AuthConfiguration?)
    private static final String issuer = "https://accounts.google.com";
    private static final String authorization_endpoint = "https://accounts.google.com/o/oauth2/v2/auth";
    private static final String token_endpoint = "https://oauth2.googleapis.com/token";
    private static final String clientId = "1051168419525-5nl60mkugb77p9j194mrh287p1e0ahfi.apps.googleusercontent.com";
    private static final String clientSecret = "XT_MIsSv_aUCGollauCaJY8S";
    private static final String redirectUri = "http://localhost:8080/authenticate"; // TODO: should redirect URI be the initially requested URI


    public static String getChallengeUri(HttpSession session)
    {
        String antiForgeryToken;
        synchronized (session)
        {
            antiForgeryToken = (session.getAttribute(CSRF_TOKEN_ATTRIBUTE) == null)
                ? new BigInteger(130, new SecureRandom()).toString(32)
                : (String)session.getAttribute(CSRF_TOKEN_ATTRIBUTE);
            session.setAttribute(CSRF_TOKEN_ATTRIBUTE, antiForgeryToken);
        }

        return authorization_endpoint +
            "?client_id=" + clientId +
            "&redirect_uri=" + redirectUri +
            "&scope=openid%20email" +
            "&state=" + antiForgeryToken +
            "&response_type=code";
    }

    @Override
    public String getAuthMethod()
    {
        return Constraint.__GOOGLE_AUTH;
    }

    @Override
    public UserIdentity login(String username, Object password, ServletRequest request)
    {

        UserIdentity user = super.login(username, password, request);
        if (user != null)
        {

            HttpSession session = ((HttpServletRequest)request).getSession(true);
            Authentication cached = new SessionAuthentication(getAuthMethod(), user, password);
            session.setAttribute(SessionAuthentication.__J_AUTHENTICATED, cached);
        }
        return user;
    }

    @Override
    public Authentication validateRequest(ServletRequest req, ServletResponse res, boolean mandatory) throws ServerAuthException
    {
        final HttpServletRequest request = (HttpServletRequest)req;
        final HttpServletResponse response = (HttpServletResponse)res;
        final Request baseRequest = Request.getBaseRequest(request);
        final Response baseResponse = baseRequest.getResponse();

        if (!mandatory)
            return new DeferredAuthentication(this);

        try
        {
            // If contains an ID Token we can validate request
            // Otherwise issue a challenge to redirect URI

            String authCode = request.getParameter("code");
            if (authCode != null)
            {
                // TODO: Attempt to authenticate the user
                LOG.warn("authentication request with code {}", authCode);
                return null;
            }

            // Look for cached authentication
            HttpSession session = request.getSession(false);
            Authentication authentication = session == null ? null : (Authentication)session.getAttribute(SessionAuthentication.__J_AUTHENTICATED);
            if (authentication != null)
            {
                // TODO: check whether auth has been revoked (loginService.validate())
                LOG.warn("we have authentication cached in session {}", authentication);
            }

            // send a challenge to authenticate with google and send us auth code
            String challengeUri = getChallengeUri(request.getSession());
            response.setStatus(HttpStatus.SEE_OTHER_303);
            response.setHeader(HttpHeader.LOCATION.asString(), challengeUri);
            return Authentication.SEND_CONTINUE;
        }
        catch (Throwable t)
        {
            // TODO: make sure exception doesn't contain any sensitive info
            throw new ServerAuthException(t);
        }
    }

    @Override
    public boolean secureResponse(ServletRequest request, ServletResponse response, boolean mandatory, Authentication.User validatedUser) throws ServerAuthException
    {
        return false;
    }
}
