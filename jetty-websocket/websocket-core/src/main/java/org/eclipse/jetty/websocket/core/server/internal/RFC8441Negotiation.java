//
//  ========================================================================
//  Copyright (c) 1995-2019 Mort Bay Consulting Pty. Ltd.
//  ------------------------------------------------------------------------
//  All rights reserved. This program and the accompanying materials
//  are made available under the terms of the Eclipse Public License v1.0
//  and Apache License v2.0 which accompanies this distribution.
//
//      The Eclipse Public License is available at
//      http://www.eclipse.org/legal/epl-v10.html
//
//      The Apache License v2.0 is available at
//      http://www.opensource.org/licenses/apache2.0.php
//
//  You may elect to redistribute this code under either of these licenses.
//  ========================================================================
//

package org.eclipse.jetty.websocket.core.server.internal;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.http.BadMessageException;
import org.eclipse.jetty.io.ByteBufferPool;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.util.DecoratedObjectFactory;
import org.eclipse.jetty.websocket.core.WebSocketExtensionRegistry;
import org.eclipse.jetty.websocket.core.server.Negotiation;

public class RFC8441Negotiation extends Negotiation
{
    public RFC8441Negotiation(Request baseRequest, HttpServletRequest request, HttpServletResponse response, WebSocketExtensionRegistry registry, DecoratedObjectFactory objectFactory, ByteBufferPool bufferPool) throws BadMessageException
    {
        super(baseRequest, request, response, registry, objectFactory, bufferPool);
    }

    @Override
    public boolean isUpgrade()
    {
        if (!getBaseRequest().hasMetaData())
            return false;

        return "websocket".equals(getBaseRequest().getMetaData().getProtocol());
    }
}
