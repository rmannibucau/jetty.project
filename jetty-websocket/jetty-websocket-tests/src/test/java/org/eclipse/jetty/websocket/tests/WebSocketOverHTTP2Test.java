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

package org.eclipse.jetty.websocket.tests;

import java.net.URI;
import java.util.concurrent.TimeUnit;

import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.dynamic.HttpClientTransportDynamic;
import org.eclipse.jetty.http2.client.HTTP2Client;
import org.eclipse.jetty.http2.client.http.ClientConnectionFactoryOverHTTP2;
import org.eclipse.jetty.http2.server.HTTP2CServerConnectionFactory;
import org.eclipse.jetty.io.ClientConnector;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.thread.QueuedThreadPool;
import org.eclipse.jetty.websocket.api.Session;
import org.eclipse.jetty.websocket.api.StatusCode;
import org.eclipse.jetty.websocket.client.WebSocketClient;
import org.eclipse.jetty.websocket.server.JettyWebSocketServlet;
import org.eclipse.jetty.websocket.server.JettyWebSocketServletContainerInitializer;
import org.eclipse.jetty.websocket.server.JettyWebSocketServletFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class WebSocketOverHTTP2Test
{
    private Server server;
    private ServerConnector connector;

    @BeforeEach
    public void startServer() throws Exception
    {
        QueuedThreadPool serverThreads = new QueuedThreadPool();
        serverThreads.setName("server");
        server = new Server(serverThreads);
        connector = new ServerConnector(server, 1, 1, new HTTP2CServerConnectionFactory(new HttpConfiguration()));
        server.addConnector(connector);

        ServletContextHandler context = new ServletContextHandler(server, "/");
        context.addServlet(new ServletHolder(new JettyWebSocketServlet()
        {
            @Override
            protected void configure(JettyWebSocketServletFactory factory)
            {
                factory.addMapping("/ws/echo", (req, resp) -> new EchoSocket());
            }
        }), "/ws/*");
        JettyWebSocketServletContainerInitializer.configureContext(context);

        server.start();
    }

    @AfterEach
    public void stopServer() throws Exception
    {
        server.stop();
    }

    @Test
    public void testWebSocketOverDynamicHTTP2() throws Exception
    {
        ClientConnector clientConnector = new ClientConnector();
        clientConnector.setSelectors(1);
        ClientConnectionFactoryOverHTTP2.H2C h2c = new ClientConnectionFactoryOverHTTP2.H2C(new HTTP2Client(clientConnector));
        HttpClient httpClient = new HttpClient(new HttpClientTransportDynamic(clientConnector, h2c));
        QueuedThreadPool clientThreads = new QueuedThreadPool();
        clientThreads.setName("client");
        httpClient.setExecutor(clientThreads);

        WebSocketClient wsClient = new WebSocketClient(httpClient);
        wsClient.start();

        EventSocket wsEndPoint = new EventSocket();
        URI uri = URI.create("ws://localhost:" + connector.getLocalPort() + "/ws/echo");
        Session session = wsClient.connect(wsEndPoint, uri).get(5, TimeUnit.SECONDS);

        String text = "http2";
        session.getRemote().sendString(text);

        String message = wsEndPoint.messageQueue.poll(5, TimeUnit.SECONDS);
        assertNotNull(message);
        assertEquals(text, message);

        session.close(StatusCode.NORMAL, null);
        assertTrue(wsEndPoint.closeLatch.await(5, TimeUnit.SECONDS));
    }
}
