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

package org.jboss.sasl.scram;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import javax.crypto.Mac;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;
import org.jboss.sasl.JBossSasl;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class ScramClientFactory extends ScramFactory implements SaslClientFactory {

    private final String name;
    private final boolean plus;

    protected ScramClientFactory(final String name, final String mdAlgorithm, final String macAlgorithm, final boolean plus) {
        super(name, mdAlgorithm, macAlgorithm);
        this.name = name;
        this.plus = plus;
    }

    private static String stringOf(Object obj) {
        return obj == null ? null : obj.toString();
    }

    public SaslClient createSaslClient(final String[] mechanisms, final String authorizationId, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        if (! isIncluded(mechanisms)) {
            return null;
        }
        String bindingMode = stringOf(props.get(JBossSasl.CHANNEL_BINDING_MODE));
        String bindingType = stringOf(props.get(JBossSasl.CHANNEL_BINDING_TYPE));
        Object bindingData = props.get(JBossSasl.CHANNEL_BINDING_DATA);
        byte[] castBindingData = bindingData instanceof byte[] ? (byte[]) bindingData : null;
        if (bindingType == null || castBindingData == null) {
            bindingMode = JBossSasl.CBM_FORBIDDEN;
        }
        if (bindingMode == null) {
            bindingMode = JBossSasl.CBM_ALLOWED;
        }
        if (plus) {
            // This mechanism inherently requires channel binding
            if (! (bindingMode.equals(JBossSasl.CBM_REQUIRED) || bindingMode.equals(JBossSasl.CBM_ALLOWED))) {
                return null;
            }
        } else if (bindingMode.equals(JBossSasl.CBM_REQUIRED)) {
            // Cannot perform channel binding for this mechanism
            return null;
        }
        final String messageDigestName = getMdAlgorithm();
        final String macName = getMacAlgorithm();
        if (macName == null) {
            return null;
        }
        final ScramClient client;
        try {
            final MessageDigest messageDigest = MessageDigest.getInstance(messageDigestName);
            final Mac mac = Mac.getInstance(macName);
            client = new ScramClient(name, messageDigest, mac, protocol, serverName, cbh, authorizationId, props, plus, bindingType, castBindingData);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
        client.init();
        return client;
    }
}
