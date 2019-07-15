package org.eclipse.jetty.security;

import javax.servlet.ServletRequest;

import org.eclipse.jetty.server.UserIdentity;

public class GoogleLoginService implements LoginService
{
    public GoogleLoginService()
    {

    }

    @Override
    public String getName()
    {
        return null;
    }

    @Override
    public UserIdentity login(String identifier, Object credentials, ServletRequest request)
    {
        return null;
    }

    @Override
    public boolean validate(UserIdentity user)
    {
        return false;
    }

    @Override
    public IdentityService getIdentityService()
    {
        return null;
    }

    @Override
    public void setIdentityService(IdentityService service)
    {

    }

    @Override
    public void logout(UserIdentity user)
    {

    }
}
