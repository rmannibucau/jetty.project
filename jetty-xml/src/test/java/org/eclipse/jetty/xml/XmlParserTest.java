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

package org.eclipse.jetty.xml;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URL;

import org.eclipse.jetty.util.resource.Resource;
import org.junit.jupiter.api.Test;

public class XmlParserTest
{
    @Test
    public void testXmlParser() throws Exception
    {
        XmlParser parser = new XmlParser();

        URL configURL = XmlConfiguration.class.getResource("configure_10_0.dtd");
        parser.redirectEntity("configure_10_0.dtd", configURL);
        parser.redirectEntity("http://jetty.eclipse.org/configure.dtd", configURL);
        parser.redirectEntity("-//Mort Bay Consulting//DTD Configure//EN", configURL);

        URL url = XmlParserTest.class.getClassLoader().getResource("org/eclipse/jetty/xml/configureWithAttr.xml");
        XmlParser.Node testDoc = parser.parse(url.toString());
        String testDocStr = testDoc.toString().trim();

        assertTrue(testDocStr.startsWith("<Configure"));
        assertTrue(testDocStr.endsWith("</Configure>"));
    }

}
