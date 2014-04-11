/* This file is part of the Raven Library.
 *
 * Copyright (c) 2005 Matthew Lavy and Alistair Turnbull.
 * Copyright (c) 2014 Tom Oinn
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * The library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 */
package gs.spri.raven.core;

import static java.net.HttpURLConnection.HTTP_OK;

import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.Iterator;

/**
 * Class to validate Token objects in the context of a Request. Configured with
 * a key store and key prefix.
 */
public final class Authenticator {

    /**
     * Define the clock skew allowed to be 60s, the actual use of the clock skew
     * parameter in the raven HTTP interactions is deprecated but this allows
     * requests to be validated provided the overall exchange hasn't taken more
     * than a minute.
     */
    private final long LEGAL_CLOCK_SKEW = 60000l;

    /**
     * Prefix for keys within the key store.
     */
    private final String keyPrefix;

    /**
     * The key store to use.
     */
    private final KeyStore keys;

    /**
     * Create a reusable authenticator configured with the given key-store and
     * key prefix.
     * 
     * @param keys
     *            the key store from which certificates can be extracted to
     *            verify tokens.
     * @param keyPrefix
     *            the prefix for keys in the store.
     */
    public Authenticator(KeyStore keys, String keyPrefix) {
	this.keys = keys;
	this.keyPrefix = keyPrefix;
    }

    /**
     * Validate a token against a request object, catching the exception thrown
     * by the validateTokenAgainstRequest method.
     * 
     * @param r
     *            the request.
     * @param t
     *            the token.
     * @return true if the token is valid in the context of the specified
     *         request, false otherwise.
     */
    public final boolean isTokenValid(Request r, Token t) {
	try {
	    validateTokenAgainstRequest(r, t);
	    return true;
	} catch (RavenException re) {
	    return false;
	}
    }

    /**
     * Validates a token and request object, using the configured key-store to
     * do cryptographic verification of the token and checking against the
     * request object to ensure that the token is one that matches the request.
     * 
     * @throws RavenException
     *             if any validation failures occur.
     */
    public final void validateTokenAgainstRequest(Request r, Token t)
	    throws RavenException {

	if (r == null)
	    throw new RavenException("No request specified!");
	if (t == null)
	    throw new RavenException("No token specified!");

	// Check that an acceptable combination of parameters is present.
	if (!r.ver.equals(t.ver))
	    throw new RavenException("Incorrect protocol version");

	// Check that the status was 200 OK.
	if (t.status != HTTP_OK)
	    throw new RavenAuthenticationException(t.msg, t.status);

	// Check that the issue date is not in the future.
	final long now = System.currentTimeMillis();
	if (t.getIssue().getTime() > now + LEGAL_CLOCK_SKEW)
	    throw new RavenException("Response time is in the future");

	// Check URL is one we expected.
	if (!r.url.equals(t.url))
	    throw new RavenException("Non-matching URL");

	// Check that principal exists.
	if ("".equals(t.principal))
	    throw new RavenException("Principal required but missing");

	// Check that auth or sso exist and are acceptable.
	if (!"".equals(t.auth) ^ t.sso.size() == 0)
	    throw new RavenException("Exactly one of SSO or Auth must be set");
	if (r.iact == Boolean.TRUE) {
	    if ("".equals(t.auth))
		throw new RavenException("Auth is missing");
	    if (r.aauth != null && !r.aauth.contains(t.auth))
		throw new RavenException("Auth method is unacceptable");
	} else if (r.iact == Boolean.FALSE) {
	    if (t.sso.size() == 0)
		throw new RavenException("SSO is missing");
	    boolean isOkay = r.aauth == null;
	    for (Iterator<String> it = t.sso.iterator(); !isOkay
		    && it.hasNext();) {
		final String s = (String) it.next();
		isOkay |= r.aauth.contains(s);
	    }
	    if (!isOkay)
		throw new RavenException("SSO method is unacceptable");
	}

	// Check that params match.
	if (r.params != null && !r.params.equals(t.params))
	    throw new RavenException("Params do not match");

	// Check that kid exists.
	if ("".equals(t.kid))
	    throw new RavenException("kid is missing");

	// Check signature.
	if (!t.hasSig())
	    throw new RavenException("Signature is missing");
	try {
	    final String certFile = this.keyPrefix + t.kid;
	    final Certificate cert = this.keys.getCertificate(certFile);
	    if (cert == null)
		throw new RavenException("Cannot read certificate: " + certFile);
	    final Signature sig = Signature.getInstance("SHA1withRSA");
	    sig.initVerify(cert);
	    sig.update(t.signedString);
	    if (!sig.verify(t.sig))
		throw new RavenException("Signature does not match plaintext");
	} catch (InvalidKeyException e) {
	    throw new RavenException(e.getMessage());
	} catch (KeyStoreException e) {
	    throw new RavenException(e.getMessage());
	} catch (NoSuchAlgorithmException e) {
	    throw new RavenException(e.getMessage());
	} catch (SignatureException e) {
	    throw new RavenException(e.getMessage());
	}
    }

}
