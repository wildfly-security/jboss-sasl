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
import java.security.Provider;
import java.security.Security;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.jboss.sasl.JBossSaslProvider;

/**
 * A {@link SaslServerFactory} to locate the default GSSAPI mechanism and wrap it in our own version to ensure our identity is
 * set on the access control context.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class GssapiServerFactory implements SaslServerFactory {

    public static final String GSSAPI = "GSSAPI";
    static final String SUBJECT_FACTORY = "org.jboss.sasl.gssapi.subject_factory";

    private static final String GSSAPI_KEY = SaslServerFactory.class.getSimpleName() + "." + GSSAPI;

    @Override
    public String[] getMechanismNames(Map<String, ?> props) {
        if (props.containsKey(SUBJECT_FACTORY) && findFactoryForGssapi(props) != null) {
            return new String[] { GSSAPI };
        } else {
            return new String[] {};
        }
    }

    @Override
    public SaslServer createSaslServer(final String mechanism, final String protocol, final String serverName, final Map<String, ?> props,
            final CallbackHandler cbh) throws SaslException {
        SubjectFactory factory = (SubjectFactory) props.get(SUBJECT_FACTORY);
        if (factory != null) {
            final SaslServerFactory saslFactory = findFactoryForGssapi(props);
            if (saslFactory != null) {
                final SubjectIdentity identity = factory.getSubjectIdentity(protocol, serverName);
                if (identity != null)
                    try {
                        return Subject.doAs(identity.getSubject(), new PrivilegedExceptionAction<SaslServer>() {

                            @Override
                            public SaslServer run() throws SaslException {
                                SaslServer realServer = saslFactory.createSaslServer(mechanism, protocol, serverName, props, cbh);
                                return new GssapiServer(identity, realServer);
                            }
                        });
                    } catch (PrivilegedActionException e) {
                        identity.dispose();
                        throw (SaslException)e.getException();
                    }

            }
        }

        return null;
    }

    private SaslServerFactory findFactoryForGssapi(Map<String, ?> props) {
        Provider[] providers = Security.getProviders();

        for (Provider current : providers) {
            // Looking for the first provider that is not our provider.
            if (current instanceof JBossSaslProvider == false) {
                String gssapiFactory = current.getProperty(GSSAPI_KEY);

                if (gssapiFactory != null) {
                    try {
                        SaslServerFactory theFactory = Class.forName(gssapiFactory, true, current.getClass().getClassLoader())
                                .asSubclass(SaslServerFactory.class).newInstance();
                        for (String mech : theFactory.getMechanismNames(props)) {
                            if (GSSAPI.equals(mech)) {
                                return theFactory;
                            }
                        }
                    } catch (InstantiationException e) {
                    } catch (IllegalAccessException e) {
                    } catch (ClassNotFoundException e) {
                    }
                }
            }
        }

        return null;
    }

}
