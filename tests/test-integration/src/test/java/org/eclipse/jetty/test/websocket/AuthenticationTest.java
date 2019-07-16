package org.eclipse.jetty.test.websocket;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Map;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http.HttpStatus;
import org.eclipse.jetty.security.ConstraintMapping;
import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.security.HashLoginService;
import org.eclipse.jetty.security.SecurityHandler;
import org.eclipse.jetty.security.UserStore;
import org.eclipse.jetty.security.authentication.FormAuthenticator;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.util.ajax.JSON;
import org.eclipse.jetty.util.security.Constraint;
import org.eclipse.jetty.util.security.Credential;

public class AuthenticationTest
{
    private static final String CSRF_TOKEN_ATTRIBUTE = "CSRF_TOKEN_ATTRIBUTE";

    private static final String issuer = "https://accounts.google.com";
    private static final String authorization_endpoint = "https://accounts.google.com/o/oauth2/v2/auth";
    private static final String token_endpoint = "https://oauth2.googleapis.com/token";

    private static final String clientId = "1051168419525-5nl60mkugb77p9j194mrh287p1e0ahfi.apps.googleusercontent.com";
    private static final String clientSecret = "XT_MIsSv_aUCGollauCaJY8S";
    private static final String redirectUri = "http://localhost:8080/authenticate";

    public static Map<String, String> decodeAndVerifyIdToken(String jwt) throws IOException
    {
        // TODO: in production this verification should be done locally with appropriate libraries
        // NOTE: it is not necessary to check signature if this comes directly from google (authorisation code flow)
        final String tokenInfoEndpoint = "https://oauth2.googleapis.com/tokeninfo";
        URL url = new URL(tokenInfoEndpoint+"?id_token="+jwt);
        InputStream content = (InputStream)url.getContent();
        return (Map)JSON.parse(new String(content.readAllBytes()));
    }

    public static Map<String, String> getIdToken(String authCode) throws IOException
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

    public static void main(String[] args) throws Exception
    {
        Server server = new Server(8080);

        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/");
        //context.setSecurityHandler(getSecurityHandler());
        server.setHandler(context);

        context.addServlet(AuthenticateServlet.class, "/authenticate");
        context.addServlet(SecureServlet.class, "/secure");
        context.addServlet(WelcomeServlet.class, "/");

        server.start();
        server.join();
    }

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


    public static class WelcomeServlet extends HttpServlet
    {
        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException
        {
            String authenticateUri = getChallengeUri(request.getSession());
            response.setContentType("text/html");
            response.setStatus(HttpServletResponse.SC_OK);
            response.getWriter().println("<h1>Welcome</h1>");
            response.getWriter().println("<a href=\""+ authenticateUri +"\">authenticate</href>");
        }
    }

    public static class AuthenticateServlet extends HttpServlet
    {
        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException
        {
            // Verify anti-forgery state token
            String antiForgeryToken = (String)request.getSession().getAttribute(CSRF_TOKEN_ATTRIBUTE);
            if (antiForgeryToken == null || !antiForgeryToken.equals(request.getParameter("state")))
            {
                response.sendError(HttpStatus.UNAUTHORIZED_401, "Invalid state parameter");
                return;
            }

            try
            {
                // Get the authorization code used to be used to get the user info from google
                String authCode = request.getParameter("code");

                // Use the auth code to get the id token from the OpenID Provider
                Map<String, String> responseMap = getIdToken(authCode);
                System.err.println("responseMap: " + responseMap);
                String jwt = responseMap.get("id_token");

                // Decode the id_token JWT to get the user information
                Map<String, String> userInfo = decodeAndVerifyIdToken(jwt);
                System.err.println("userInfo" + userInfo);
            }
            catch (Throwable t)
            {
                // Exception message may contain sensitive information
                response.sendError(HttpStatus.UNAUTHORIZED_401, "Could not authenticate user");
                return;
            }

            // Successful authentication
            response.setStatus(HttpStatus.SEE_OTHER_303);
            response.setHeader(HttpHeader.LOCATION.asString(), "http://localhost:8080/secure");
        }
    }

    public static class SecureServlet extends HttpServlet
    {
        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException
        {
            response.setContentType("text/html");
            response.setStatus(HttpServletResponse.SC_OK);
            response.getWriter().println("<h1>Secure Zone</h1>");
            response.getWriter().println("<a href=\"/\">home</href><br>");
        }
    }

    private static SecurityHandler getSecurityHandler()
    {
        // Configure UserStore
        UserStore userStore = new UserStore();
        userStore.addUser("admin", Credential.getCredential("password"), new String[]{"user"});

        // Configure LoginService
        HashLoginService loginService = new HashLoginService();
        loginService.setUserStore(userStore);
        loginService.setName("loginService");

        // Configure Constraints
        Constraint constraint = new Constraint();
        constraint.setName("MyAuth");
        constraint.setAuthenticate(true);
        constraint.setRoles(new String[] {"user"});

        // Configure Constraint Mapping
        ConstraintMapping mapping = new ConstraintMapping();
        mapping.setPathSpec("/secure/*");
        mapping.setConstraint(constraint);

        // Configure Handler
        ConstraintSecurityHandler securityHandler = new ConstraintSecurityHandler();
        securityHandler.setConstraintMappings(Collections.singletonList(mapping));
        securityHandler.setAuthenticator(new FormAuthenticator()); // TODO: set up
        securityHandler.setLoginService(loginService);

        return securityHandler;
    }
}
