package org.eclipse.jetty.security;

import java.security.Principal;

public class GoogleUserPrincipal implements Principal
{
    private final String userId;

    public GoogleUserPrincipal(String userId)
    {
        this.userId = userId;
    }

    @Override
    public boolean equals(Object p)
    {
        if (!(p instanceof GoogleUserPrincipal))
            return false;

        return getName().equals(((GoogleUserPrincipal)p).getName());
    }

    @Override
    public int hashCode()
    {
        return getName().hashCode();
    }

    @Override
    public String getName()
    {
        return this.userId;
    }

    @Override
    public String toString()
    {
        return getName();
    }
}