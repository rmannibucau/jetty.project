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

package org.eclipse.jetty.websocket.core;

import org.eclipse.jetty.io.ByteBufferPool;
import org.eclipse.jetty.util.Callback;
import org.eclipse.jetty.util.annotation.ManagedAttribute;
import org.eclipse.jetty.util.annotation.ManagedObject;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.Logger;
import org.eclipse.jetty.websocket.core.internal.WebSocketCoreSession;

@ManagedObject("Abstract Extension")
public abstract class AbstractExtension implements Extension
{
    private final Logger log;
    private ByteBufferPool bufferPool;
    private ExtensionConfig config;
    private OutgoingFrames nextOutgoing;
    private IncomingFrames nextIncoming;
    private WebSocketCoreSession coreSession;

    public AbstractExtension()
    {
        log = Log.getLogger(this.getClass());
    }

    @Override
    public void init(ExtensionConfig config, ByteBufferPool bufferPool)
    {
        this.config = config;
        this.bufferPool = bufferPool;
    }

    public ByteBufferPool getBufferPool()
    {
        return bufferPool;
    }

    @Override
    public ExtensionConfig getConfig()
    {
        return config;
    }

    @Override
    public String getName()
    {
        return config.getName();
    }

    @ManagedAttribute(name = "Next Incoming Frame Handler", readonly = true)
    public IncomingFrames getNextIncoming()
    {
        return nextIncoming;
    }

    @ManagedAttribute(name = "Next Outgoing Frame Handler", readonly = true)
    public OutgoingFrames getNextOutgoing()
    {
        return nextOutgoing;
    }

    @Override
    public boolean isRsv1User()
    {
        return false;
    }

    @Override
    public boolean isRsv2User()
    {
        return false;
    }

    @Override
    public boolean isRsv3User()
    {
        return false;
    }

    @Override
    public boolean allowFragmentation()
    {
        return true;
    }

    @Override
    public boolean copyRsvBitOnFragment()
    {
        return true;
    }

    protected void nextIncomingFrame(Frame frame, Callback callback)
    {
        log.debug("nextIncomingFrame({})", frame);
        this.nextIncoming.onFrame(frame, callback);
    }

    protected void nextOutgoingFrame(Frame frame, Callback callback, boolean batch)
    {
        log.debug("nextOutgoingFrame({})", frame);
        this.nextOutgoing.sendFrame(frame, callback, batch);
    }

    @Override
    public void setNextIncomingFrames(IncomingFrames nextIncoming)
    {
        this.nextIncoming = nextIncoming;
    }

    @Override
    public void setNextOutgoingFrames(OutgoingFrames nextOutgoing)
    {
        this.nextOutgoing = nextOutgoing;
    }

    @Override
    public void setWebSocketCoreSession(WebSocketCoreSession coreSession)
    {
        this.coreSession = coreSession;
    }

    protected WebSocketCoreSession getWebSocketCoreSession()
    {
        return coreSession;
    }

    @Override
    public String toString()
    {
        return String.format("%s[%s]", this.getClass().getSimpleName(), config.getParameterizedName());
    }
}
