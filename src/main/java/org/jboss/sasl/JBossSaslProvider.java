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

package org.jboss.sasl;

import static org.jboss.sasl.anonymous.AbstractAnonymousFactory.ANONYMOUS;
import static org.jboss.sasl.plain.PlainServerFactory.PLAIN;
import static org.jboss.sasl.digest.DigestMD5ServerFactory.DIGEST_MD5;
import static org.jboss.sasl.localuser.LocalUserSaslFactory.JBOSS_LOCAL_USER;
import static org.jboss.sasl.scram.ScramSha1ClientFactory.SCRAM_SHA_1;
import static org.jboss.sasl.scram.ScramSha1PlusClientFactory.SCRAM_SHA_1_PLUS;
import static org.jboss.sasl.scram.ScramSha256ClientFactory.SCRAM_SHA_256;
import static org.jboss.sasl.scram.ScramSha256PlusClientFactory.SCRAM_SHA_256_PLUS;
import static org.jboss.sasl.scram.ScramSha384ClientFactory.SCRAM_SHA_384;
import static org.jboss.sasl.scram.ScramSha384PlusClientFactory.SCRAM_SHA_384_PLUS;
import static org.jboss.sasl.scram.ScramSha512ClientFactory.SCRAM_SHA_512;
import static org.jboss.sasl.scram.ScramSha512PlusClientFactory.SCRAM_SHA_512_PLUS;

import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslServerFactory;
import java.security.Provider;

import org.jboss.sasl.anonymous.AnonymousClientFactory;
import org.jboss.sasl.anonymous.AnonymousServerFactory;
import org.jboss.sasl.digest.DigestMD5ClientFactory;
import org.jboss.sasl.digest.DigestMD5ServerFactory;
import org.jboss.sasl.plain.PlainServerFactory;
import org.jboss.sasl.localuser.LocalUserClientFactory;
import org.jboss.sasl.localuser.LocalUserServerFactory;
import org.jboss.sasl.scram.ScramSha1ClientFactory;
import org.jboss.sasl.scram.ScramSha1PlusClientFactory;
import org.jboss.sasl.scram.ScramSha256ClientFactory;
import org.jboss.sasl.scram.ScramSha256PlusClientFactory;
import org.jboss.sasl.scram.ScramSha384ClientFactory;
import org.jboss.sasl.scram.ScramSha384PlusClientFactory;
import org.jboss.sasl.scram.ScramSha512ClientFactory;
import org.jboss.sasl.scram.ScramSha512PlusClientFactory;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class JBossSaslProvider extends Provider {

    private static final long serialVersionUID = 7613128233053194670L;

    private static final String INFO = "JBoss SASL Provider " + getVersionString();

    private static final String SASL_CLIENT_FACTORY = SaslClientFactory.class.getSimpleName();

    private static final String SASL_SERVER_FACTORY = SaslServerFactory.class.getSimpleName();

    private static final String DOT = ".";

    /**
     * Construct a new instance.
     */
    public JBossSaslProvider() {
        super("jboss-sasl", 1.0, INFO);
        // NOTE: make sure that all client and server factories listed here also end up in the META-INF/services files.
        put(SASL_CLIENT_FACTORY + DOT + ANONYMOUS, AnonymousClientFactory.class.getName());
        put(SASL_SERVER_FACTORY + DOT + ANONYMOUS, AnonymousServerFactory.class.getName());
        put(SASL_SERVER_FACTORY + DOT + PLAIN, PlainServerFactory.class.getName());
        put(SASL_CLIENT_FACTORY + DOT + DIGEST_MD5, DigestMD5ClientFactory.class.getName());
        put(SASL_SERVER_FACTORY + DOT + DIGEST_MD5, DigestMD5ServerFactory.class.getName());
        put(SASL_SERVER_FACTORY + DOT + JBOSS_LOCAL_USER, LocalUserServerFactory.class.getName());
        put(SASL_CLIENT_FACTORY + DOT + JBOSS_LOCAL_USER, LocalUserClientFactory.class.getName());
        put(SASL_CLIENT_FACTORY + DOT + SCRAM_SHA_1, ScramSha1ClientFactory.class.getName());
        put(SASL_CLIENT_FACTORY + DOT + SCRAM_SHA_1_PLUS, ScramSha1PlusClientFactory.class.getName());
        put(SASL_CLIENT_FACTORY + DOT + SCRAM_SHA_256, ScramSha256ClientFactory.class.getName());
        put(SASL_CLIENT_FACTORY + DOT + SCRAM_SHA_256_PLUS, ScramSha256PlusClientFactory.class.getName());
        put(SASL_CLIENT_FACTORY + DOT + SCRAM_SHA_384, ScramSha384ClientFactory.class.getName());
        put(SASL_CLIENT_FACTORY + DOT + SCRAM_SHA_384_PLUS, ScramSha384PlusClientFactory.class.getName());
        put(SASL_CLIENT_FACTORY + DOT + SCRAM_SHA_512, ScramSha512ClientFactory.class.getName());
        put(SASL_CLIENT_FACTORY + DOT + SCRAM_SHA_512_PLUS, ScramSha512PlusClientFactory.class.getName());
    }

    /**
     * Get the version string of the JBoss SASL provider.
     *
     * @return the version string.
     */
    public static String getVersionString() {
        return "NOT SET";
    }

}
