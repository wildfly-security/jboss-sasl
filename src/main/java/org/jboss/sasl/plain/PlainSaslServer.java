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

package org.jboss.sasl.plain;

import static org.jboss.sasl.plain.PlainServerFactory.PLAIN;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.SaslException;

import org.jboss.sasl.callback.VerifyPasswordCallback;
import org.jboss.sasl.util.AbstractSaslServer;
import org.jboss.sasl.util.Charsets;
import org.jboss.sasl.util.SaslState;
import org.jboss.sasl.util.SaslStateContext;

/**
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class PlainSaslServer extends AbstractSaslServer {


    protected String authorizedId;

    private final SaslState INITIAL = new SaslState() {

        private static final byte UTF8NUL = 0x00;

        public byte[] evaluateMessage(final SaslStateContext context, final byte[] message) throws SaslException {
            int length = message.length;
            if (length == 0) {
                // need initial challenge
                return NO_BYTES;
            } else {
                // Define an upper limit on accepted message so we don't accept overly large messages.
                if (length > 65536) {
                    throw new SaslException("Authentication message is too long");
                }

                String[] parts = split(message);
                String authcid;
                String authzid;
                String passwd;
                if (parts.length == 2) {
                    authcid = parts[0];
                    authzid = authcid;
                    passwd = parts[1];
                } else if (parts.length == 3) {
                    authzid = parts[0];
                    authcid = parts[1];
                    passwd = parts[2];
                } else {
                    throw new SaslException("Invalid number of message parts (" + parts.length + ")");
                }
                
                // By this point we have already created the Strings no point checking the length as the
                // memory is already allocated.

                // The message has now been parsed, split and converted to UTF-8 Strings
                // now it is time to use the CallbackHandler to validate the supplied credentials.

                // First verify username and password.

                NameCallback ncb = new NameCallback("PLAIN authentication identity", authcid);
                VerifyPasswordCallback vpc = new VerifyPasswordCallback(passwd);

                handleCallbacks(ncb, vpc);

                if (vpc.isVerified() == false) {
                    throw new SaslException("PLAIN password not verified by CallbackHandler");
                }

                // Now check the authorization id

                AuthorizeCallback acb = new AuthorizeCallback(authcid, authzid);
                handleCallbacks(acb);

                if (acb.isAuthorized() == true) {
                    authorizedId = acb.getAuthorizedID();
                } else {
                    throw new SaslException("PLAIN: " + authcid +
                            " is not authorized to act as " + authzid);
                }

                // negotiationComplete must only be called after the authorizedId is set.
                context.negotiationComplete();
                return null;
            }
        }

        private String[] split(byte[] message) throws SaslException {
            String authorizationId = null;
            String authenticationId;
            String password;

            int startPos = 0;

            int nextNul;
            int length;
            // Find the authorization ID
            nextNul = nextNul(message, startPos, true);
            if (nextNul > 0) {
                length = length(nextNul, message.length, startPos);
                authorizationId = new String(message, startPos, length, Charsets.UTF_8);
                startPos += length + 1;
            } else {
                startPos++;
            }

            // Find the authentication ID
            nextNul = nextNul(message, startPos, true);
            length = length(nextNul, message.length, startPos);
            authenticationId = new String(message, startPos, length, Charsets.UTF_8);
            startPos += length + 1;

            // Find the password
            nextNul = nextNul(message, startPos, false);
            // Verify there is no nul after the password.
            if (nextNul > -1) {
                throw new SaslException("PLAIN: Invalid message format. (Too many delimiters)");
            }

            length = length(nextNul, message.length, startPos);
            password = new String(message, startPos, length, Charsets.UTF_8);
            startPos += length + 1;

            if (authorizationId == null) {
                return new String[] { authenticationId, password };
            } else {
                return new String[] { authorizationId, authenticationId, password };
            }
        }

        /**
         * Find the next UTF8 NUL in the message.
         *
         * @param message - The message to search.
         * @param startPos - The point within the message tostart the search from.
         * @return The position of the next nul byte.
         */
        private int nextNul(final byte[] message, final int startPos, final boolean mandatory) throws SaslException {
            int nulpos = -1;

            for (int i = startPos; i < message.length && nulpos < 0; i++) {
                if (message[i] == UTF8NUL)
                    nulpos = i;
            }

            if (mandatory && nulpos < 0) {
                throw new SaslException("PLAIN: Invalid message format. (Missing delimiter)");
            }

            return nulpos;
        }

        /**
         * Calculate the length of the field based on the position of the nul, the length of the message
         * and the starting point.
         *
         * @param nulPos
         * @param messageLength
         * @param startPos
         * @return
         */
        private int length(final int nulPos, final int messageLength, final int startPos) {
            return nulPos < 0 ? messageLength - startPos : nulPos - startPos;
        }

    };

    /**
     * Construct a new instance.
     *
     * @param protocol        the protocol
     * @param serverName      the server name
     * @param callbackHandler the callback handler
     */
    public PlainSaslServer(final String protocol, final String serverName, final CallbackHandler callbackHandler) {
        super(PLAIN, protocol, serverName, callbackHandler);
        getContext().setNegotiationState(INITIAL);
    }

    public String getAuthorizationID() {
        if (isComplete()) {
            return authorizedId;
        } else {
            throw new IllegalStateException(
                    "PLAIN server negotiation not complete");
        }
    }

}
