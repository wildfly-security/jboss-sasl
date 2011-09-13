/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2011, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.jboss.sasl.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.jboss.sasl.digest.DigestMD5Server;
import org.jboss.sasl.digest.DigestMD5ServerFactory;
import org.junit.Test;

/**
 * A test case to test the server side of the Digest mechanism.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class DigestTest extends BaseTestCase {

    private static final String DIGEST = "DIGEST-MD5";

    private static final String REALM_PROPERTY =
            "com.sun.security.sasl.digest.realm";

    /*
    *  Mechanism selection tests.
    */

    @Test
    public void testPolicyIndirect_Server() throws Exception {
        Map<String, Object> props = new HashMap<String, Object>();

        // If we specify DIGEST with no policy restrictions an DigestMD5Server should be returned.
        CallbackHandler serverCallback = new ServerCallbackHandler("George", "gpwd".toCharArray());
        SaslServer server = Sasl.createSaslServer(DIGEST, "TestProtocol", "TestServer", props, serverCallback);
        assertEquals(DigestMD5Server.class, server.getClass());
    }

    @Test
    public void testPolicyDirect_Server() {
        SaslServerFactory factory = obtainSaslServerFactory(DigestMD5ServerFactory.class);
        assertNotNull("SaslServerFactory not registered", factory);

        String[] mechanisms;
        Map<String, Object> props = new HashMap<String, Object>();

        // No properties.
        mechanisms = factory.getMechanismNames(props);
        assertSingleMechanism(DIGEST, mechanisms);
    }

    /*
     *  Normal SASL Client/Server interaction.
     */

    /**
     * Test a successful exchange using the DIGEST mechanism.
     */
    @Test
    public void testSuccessfulExchange() throws Exception {
        CallbackHandler serverCallback = new ServerCallbackHandler("George", "gpwd".toCharArray());
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(REALM_PROPERTY, "TestRealm");
        SaslServer server = Sasl.createSaslServer(DIGEST, "TestProtocol", "TestServer", serverProps, serverCallback);

        CallbackHandler clientCallback = new ClientCallbackHandler("George", "gpwd".toCharArray());
        SaslClient client = Sasl.createSaslClient(new String[]{DIGEST}, "George", "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

        assertFalse(client.hasInitialResponse());
        byte[] message = server.evaluateResponse(new byte[0]);

        message = client.evaluateChallenge(message);
        server.evaluateResponse(message);
        assertTrue(server.isComplete());
        assertEquals("George", server.getAuthorizationID());
    }

    /**
     * Test that verification fails for a bad password.
     */
    @Test
    public void testBadPassword() throws Exception {
        CallbackHandler serverCallback = new ServerCallbackHandler("George", "bad".toCharArray());
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(REALM_PROPERTY, "TestRealm");
        SaslServer server = Sasl.createSaslServer(DIGEST, "TestProtocol", "TestServer", serverProps, serverCallback);

        CallbackHandler clientCallback = new ClientCallbackHandler("George", "gpwd".toCharArray());
        SaslClient client = Sasl.createSaslClient(new String[]{DIGEST}, "George", "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

        assertFalse(client.hasInitialResponse());
        byte[] message = server.evaluateResponse(new byte[0]);

        message = client.evaluateChallenge(message);
        try {
            server.evaluateResponse(message);
            fail("Expection exception not thrown.");
        } catch (IOException e) {
        }
    }

    /**
     * Test that verification fails for a bad username.
     */
    @Test
    public void testBadUsername() throws Exception {
        CallbackHandler serverCallback = new ServerCallbackHandler("Borris", "gpwd".toCharArray());
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(REALM_PROPERTY, "TestRealm");
        SaslServer server = Sasl.createSaslServer(DIGEST, "TestProtocol", "TestServer", serverProps, serverCallback);

        CallbackHandler clientCallback = new ClientCallbackHandler("George", "gpwd".toCharArray());
        SaslClient client = Sasl.createSaslClient(new String[]{DIGEST}, "George", "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

        assertFalse(client.hasInitialResponse());
        byte[] message = server.evaluateResponse(new byte[0]);

        message = client.evaluateChallenge(message);
        try {
            server.evaluateResponse(message);
            fail("Expection exception not thrown.");
        } catch (IOException e) {
        }
    }

    /**
     * Test that verification fails for a bad realm.
     */
    @Test
    public void testBadRealm() throws Exception {
        CallbackHandler serverCallback = new ServerCallbackHandler("George", "gpwd".toCharArray());
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(REALM_PROPERTY, "TestRealm");
        SaslServer server = Sasl.createSaslServer(DIGEST, "TestProtocol", "TestServer", serverProps, serverCallback);

        CallbackHandler clientCallback = new ClientCallbackHandler("George", "gpwd".toCharArray(), "BadRealm");
        SaslClient client = Sasl.createSaslClient(new String[]{DIGEST}, "George", "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

        assertFalse(client.hasInitialResponse());
        byte[] message = server.evaluateResponse(new byte[0]);

        message = client.evaluateChallenge(message);
        try {
            server.evaluateResponse(message);
            fail("Expection exception not thrown.");
        } catch (IOException e) {
        }
    }

    /*
     *  Advanced Client/Server interaction.
     */

    // Replay previously used nonce.


}