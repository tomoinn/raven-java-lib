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

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.StringTokenizer;

/**
 * Represents authentication data received from Raven.
 * <p>
 * Documentation of fields consists of a paragraph directly lifted from the <a
 * href="http://raven.cam.ac.uk/project/waa2wls-protocol.txt">WAA2WLS Protocol
 * specification</a>, followed by our own Java-specific comments where required.
 * Omitted fields are stored as the empty string, <em>not</em> as 'null'.
 */
public class Token {

    /**
     * Constructs a Token from what the specification document calls an
     * "Encoded Response String". The string consists of "!"-separated fields in
     * a defined order: the same as the order in which the fields appear in this
     * class.
     * <p>
     * This constructor does <em>not</em> validate the response or check the
     * cryptographic signature.
     * 
     * @throws IllegalArgumentException
     *             if 'ers' does not have the correct format.
     */
    public Token(String ers) throws RavenException {
	final String[] fields = (ers + "!END").split("!");
	if (fields.length != 14)
	    throw new RavenException("Incorrect number of fields");
	this.ver = Util.decode(fields[0]);
	try {
	    final String s = Util.decode(fields[1]);
	    if (s.length() != 3)
		throw new NumberFormatException();
	    this.status = Integer.parseInt(s);
	} catch (NumberFormatException e) {
	    throw new RavenException("Bad status code");
	}
	this.msg = Util.decode(fields[2]);
	try {
	    this.issue = Util.RAVEN_DATE_FORMAT.parse(Util.decode(fields[3]));
	} catch (ParseException e) {
	    throw new RavenException("Bad issue time");
	}
	this.id = Util.decode(fields[4]);
	if ("".equals(this.id))
	    throw new RavenException("Missing ID");
	try {
	    this.url = new URL(Util.decode(fields[5])).toString();
	} catch (MalformedURLException e) {
	    throw new RavenException("Bad URL");
	}
	this.principal = Util.decode(fields[6]);
	this.auth = Util.decode(fields[7]);
	final Set<String> zsso = new HashSet<String>();
	final StringTokenizer st = new StringTokenizer(Util.decode(fields[8]),
		",", false);
	while (st.hasMoreTokens())
	    zsso.add(st.nextToken());
	this.sso = Collections.unmodifiableSet(zsso);
	try {
	    final String s = Util.decode(fields[9]);
	    if ("".equals(s)) {
		this.lifeEnd = null;
	    } else {
		final int life = Integer.parseInt(Util.decode(s));
		this.lifeEnd = new Date(System.currentTimeMillis() + 1000L
			* life);
	    }
	} catch (NumberFormatException e) {
	    throw new RavenException("Bad life");
	}
	this.params = Util.decode(fields[10]);
	this.kid = Util.decode(fields[11]);
	try {
	    this.sig = Util.decode64(Util.decode(fields[12]));
	} catch (ParseException e) {
	    throw new RavenException("Problem decoding sig: " + e.getMessage());
	}
	final int sigIndex = ers.lastIndexOf('!');
	final int kidIndex = ers.lastIndexOf('!', sigIndex - 1);
	try {
	    this.signedString = ers.substring(0, kidIndex).getBytes("US-ASCII");
	} catch (UnsupportedEncodingException xoov) {
	    throw new RuntimeException("US-ASCII not supported. They say.");
	}
    }

    /**
     * [REQUIRED] The version of the WLS protocol in use. This document
     * describes version 1 of the protocol. This will not be greater than the
     * 'ver' parameter supplied in the request.
     */
    public final String ver;

    /**
     * [REQUIRED] A three digit status code indicating the status of the
     * authentication request. '200' indicates success, other possible values
     * are [documented in the specification].
     */
    public final int status;

    /**
     * [OPTIONAL] A text message further describing the status of the
     * authentication request, suitable for display to end-user.
     * <p>
     * Always non-null (empty string if absent).
     */
    public final String msg;

    /**
     * [REQUIRED] The date and time that this authentication response was
     * created.
     * <p>
     * This is a method rather than a field because Java does not have a
     * convenient immutable Date object.
     */
    public final Date getIssue() {
	return (Date) this.issue.clone();
    }

    private final Date issue;

    /**
     * [REQUIRED] An identifier for this response. 'id', combined with 'issue'
     * provides a unique identifier for this response. 'id' is not unguessable.
     */
    public final String id;

    /**
     * [REQUIRED] The value of 'url' supplied in the 'authentication request'
     * and used to form the 'authentication response'.
     */
    public final String url;

    /**
     * [REQUIRED if status is '200', otherwise required to be empty] If present,
     * indicates the authenticated identity of the browser user.
     */
    public final String principal;

    /**
     * [REQUIRED if authentication was successfully established by interaction
     * with the user, otherwise required to be empty] This indicates which
     * authentication type was used. This value consists of a single text token
     * as described below.
     */
    public final String auth;

    /**
     * [REQUIRED if 'auth' is empty] Authentication must have been established
     * based on previous successful authentication interaction(s) with the user.
     * This indicates which authentication types were used on these occasions.
     * This value consists of a sequence of text tokens as described below,
     * separated by ','.
     */
    public final Set<String> sso;

    /**
     * [OPTIONAL] If the user has established an authenticated 'session' with
     * the WLS, this indicates the remaining life (in seconds) of that session.
     * If present, a WAA SHOULD use this to establish an upper limit to the
     * lifetime of any session that it establishes.
     * <p>
     * 'life' as described is correct only at the instant that this object is
     * constructed. We therefore convert it to an expiry Date before storing it
     * here. 'null' if absent.
     * <p>
     * This is a method rather than a field because Java does not have a
     * convenient immutable Date object.
     */
    public final Date getLifeEnd() {
	return (Date) this.lifeEnd.clone();
    }

    final Date lifeEnd;

    /**
     * [REQUIRED to be a copy of the params parameter from the request].
     */
    public final String params;

    /**
     * [REQUIRED if a signature is present] A string which identifies the RSA
     * key which will be used to form a signature supplied with the response.
     * Typically these will be small integers.
     */
    public final String kid;

    /**
     * [REQUIRED if status is 200, OPTIONAL otherwise] A public-key signature of
     * the response data constructed from the entire parameter value except
     * 'kid' and 'signature' (and their separating '!' characters) using the
     * private key identified by 'kid', the SHA-1 hash algorithm and the
     * 'RSASSA-PKCS1-v1_5' scheme as specified in PKCS #1 v2.1 [RFC 3447] and
     * the resulting signature encoded using the base64 scheme [RFC 1521] except
     * that the characters '+', '/', and '=' are replaced by '-', '.' and '_' to
     * reduce the URL-encoding overhead.
     * <p>
     * This is a method because Java does not have a convenient immutable array
     * object.
     */
    public final byte[] getSig() {
	return (byte[]) this.sig.clone();
    }

    public final boolean hasSig() {
	return this.sig.length > 0;
    }

    final byte[] sig;

    /**
     * The plaintext of which 'sig' purports to be the signature. i.e. the raw
     * response data with the 'kid' and 'signature' values removed.
     * <p>
     * This is a method because Java does not have a convenient immutable array
     * object.
     */
    public final byte[] getSignedString() {
	return (byte[]) this.signedString.clone();
    }
    
    /**
     * Returns 'true' if 'this.getToken()' exists and has not expired by 'when'.
     */
    public boolean isCurrent(Date when) {
	return lifeEnd == null || when.before(lifeEnd);
    }

    final byte[] signedString;
}