/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014, Red Hat, Inc., and individual contributors
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

package org.jboss.sasl.gssapi;

import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import javax.security.auth.Subject;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

/**
 * A simple {@link SaslServer} to wrap calls to a realm GSSAPI sasl server.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class GssapiServer implements SaslServer {

    private SubjectIdentity identity;
    private final SaslServer wrapped;

    GssapiServer(final SubjectIdentity identity, final SaslServer toWrap) {
        this.identity = identity;
        this.wrapped = toWrap;
    }

    @Override
    public String getMechanismName() {
        return wrapped.getMechanismName();
    }

    @Override
    public byte[] evaluateResponse(final byte[] response) throws SaslException {
        Subject subject = identity.getSubject();
        try {
            return Subject.doAs(subject, new PrivilegedExceptionAction<byte[]>() {

                @Override
                public byte[] run() throws SaslException {
                    return wrapped.evaluateResponse(response);
                }
            });
        } catch (PrivilegedActionException e) {
            throw (SaslException) e.getException();
        }
    }

    @Override
    public boolean isComplete() {
        return wrapped.isComplete();
    }

    @Override
    public String getAuthorizationID() {
        return wrapped.getAuthorizationID();
    }

    @Override
    public byte[] unwrap(final byte[] incoming, final int offset, final int len) throws SaslException {
        Subject subject = identity.getSubject();
        try {
            return Subject.doAs(subject, new PrivilegedExceptionAction<byte[]>() {

                @Override
                public byte[] run() throws SaslException {
                    return wrapped.unwrap(incoming, offset, len);
                }
            });
        } catch (PrivilegedActionException e) {
            throw (SaslException) e.getException();
        }
    }

    @Override
    public byte[] wrap(final byte[] outgoing, final int offset, final int len) throws SaslException {
        Subject subject = identity.getSubject();
        try {
            return Subject.doAs(subject, new PrivilegedExceptionAction<byte[]>() {

                @Override
                public byte[] run() throws SaslException {
                    return wrapped.wrap(outgoing, offset, len);
                }
            });
        } catch (PrivilegedActionException e) {
            throw (SaslException) e.getException();
        }
    }

    @Override
    public Object getNegotiatedProperty(final String propName) {
        return wrapped.getNegotiatedProperty(propName);
    }

    @Override
    public void dispose() throws SaslException {
        Subject subject = getSubject();
        try {
            Subject.doAs(subject, new PrivilegedExceptionAction<Void>() {

                @Override
                public Void run() throws SaslException {
                    wrapped.dispose();
                    return null;
                }
            });
        } catch (PrivilegedActionException e) {
            throw (SaslException) e.getException();
        }
        identity.dispose();
        identity = null;
    }

    private Subject getSubject() throws SaslException {
        if (identity != null) {
            return identity.getSubject();
        }

        throw new SaslException("dispose() has already been called on this SaslServer.");
    }

}
