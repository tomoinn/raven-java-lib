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
package gs.spri.raven;

import gs.spri.raven.core.Authenticator;
import gs.spri.raven.core.RavenException;
import gs.spri.raven.core.RavenStateException;
import gs.spri.raven.core.Request;
import gs.spri.raven.core.Token;

import java.io.IOException;
import java.net.URL;
import java.security.KeyStore;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Manages authentication against Raven, handles interaction with the Raven
 * server, and provides the utility methods needed to parse Raven data.
 * <p>
 * An application using this class must maintain a single instance of
 * RavenAuthenticator for each session. Each time a request is received, the
 * application must perform the following actions in order:
 * <ul>
 * <li>Call 'interceptLoginRequest()'. This method returns 'true' if the request
 * is a redirect from Raven. In these circumstances, the application should take
 * no further action (because a response will already have committed, typically
 * a redirection to another URL handled by the application).
 * <li>Optionally save request parameters in the session, if there are not
 * already saved request parameters. If the user needs to be asked to
 * authenticate themselves, it may take several web request/response cycles
 * during which any POST data not saved now will be lost.
 * <li>If the request is for a resource which the application wishes to protect
 * using authentication, call 'handleAuthentication()'. If this method returns
 * 'true', then the application should take no further action because a response
 * will already have committed. Typically this will be a redirection to the
 * Raven server. There are a variety of Exceptions that this method can throw to
 * indicate various authentication failures. If an Exception occurs, the
 * application should display an appropriate message and take no further action.
 * <li>Process the request using the saved request parameters, and clear the
 * saved request parameters from the session.
 * </ul>
 * 
 * @author Matthew Lavy and Alistair Turnbull
 * @version 1.0.3, 02 January 2007
 */
public class RavenAuthenticator {

    private final Authenticator auth;

    /**
     * Constructs a RavenAuthenticator object. This constructor is deprectated
     * as the clockskew parameter is no longer supported by the raven
     * authentication service.
     * 
     * @param clockSkew
     *            tolerance in milliseconds of clock difference between the
     *            local machine and the Raven server.
     * @param ravenURL
     *            the URL of the Raven server. This is the URL to which users
     *            will be redirected in order to authenticate.
     * @param interceptLoginPath
     *            a path in the URL namespace of the (local) servlet which this
     *            RavenAuthenticator can recognise as its own. Requests to this
     *            path will be intercepted by the 'interceptLoginRequest()'
     *            method. The path must be relative to the servlet root and
     *            start with a '/'.
     * @param description
     *            a text description of the resource requiring authentication,
     *            or 'null'. This value is used in 'Request.desc'.
     * @param keys
     *            the public keys used by the Raven server to sign
     *            authentication tokens.
     * @param keyPrefix
     *            the common alias prefix of the Raven keys within 'keys'.
     */
    @Deprecated
    public RavenAuthenticator(long clockSkew, String ravenURL,
	    String interceptLoginPath, String description, KeyStore keys,
	    String keyPrefix) {
	this.auth = new Authenticator(keys, keyPrefix);
	this.ravenURL = ravenURL;
	this.interceptLoginPath = interceptLoginPath;
	this.description = description;
    }

    /**
     * Constructs a RavenAuthenticator object.
     * 
     * @param ravenURL
     *            the URL of the Raven server. This is the URL to which users
     *            will be redirected in order to authenticate.
     * @param interceptLoginPath
     *            a path in the URL namespace of the (local) servlet which this
     *            RavenAuthenticator can recognise as its own. Requests to this
     *            path will be intercepted by the 'interceptLoginRequest()'
     *            method. The path must be relative to the servlet root and
     *            start with a '/'.
     * @param description
     *            a text description of the resource requiring authentication,
     *            or 'null'. This value is used in 'Request.desc'.
     * @param keys
     *            the public keys used by the Raven server to sign
     *            authentication tokens.
     * @param keyPrefix
     *            the common alias prefix of the Raven keys within 'keys'.
     */
    public RavenAuthenticator(String ravenURL, String interceptLoginPath,
	    String description, KeyStore keys, String keyPrefix) {
	this.auth = new Authenticator(keys, keyPrefix);
	this.ravenURL = ravenURL;
	this.interceptLoginPath = interceptLoginPath;
	this.description = description;
    }

    /**
     * This method recognises web requests that result from a redirection from
     * the Raven server. When one is encountered, it saves all the
     * authentication information, and redirects the client to the URL
     * originally requested. It then returns 'true' and the caller should take
     * no further action. For all other web requests, this method does nothing
     * and returns 'false'.
     * <p>
     * The test used to recognise a redirection from the Raven server is
     * 'interceptLoginPath.equals(req.getPathInfo())' where 'interceptLoginPath'
     * is the value that was passed to the constructor of this object.
     * <p>
     * This method has no side-effects on 'req' if it returns 'false'.
     * 
     * @param req
     *            the request to examine.
     * @param res
     *            the response to which to write the redirect instruction.
     * @return 'true' if the response has been written, or 'false' if the
     *         request requires further handling by the caller.
     * @throws RavenException
     *             if there is a protocol error.
     */
    public boolean interceptLoginRequest(HttpServletRequest req,
	    HttpServletResponse res) throws RavenException, IOException {
	if (!this.interceptLoginPath.equals(req.getPathInfo()))
	    return false;
	if (this.request == null)
	    throw new RavenStateException(
		    "No memory of an authentication request. This can happen if the "
			    + "user bookmarks the Raven login page.");
	final String p = req.getParameter("WLS-Response");
	if (p == null)
	    throw new RavenException("Entire WLS-Response is missing");
	this.token = new Token(p);
	res.sendRedirect(res.encodeRedirectURL(this.requestedURL));
	return true;
    }

    /**
     * This method checks that the user is authenticated by examining its
     * internal state. If so, it does nothing and returns 'false'. If the user
     * has not yet been asked to authenticate themselves, or if the
     * authentication Token has expired by 'when', it redirects the client to
     * the Raven server and returns 'true'. The client should then take no
     * further action. If the user has tried but failed to authenticate, or if
     * authentication fails for any other reason, this method throws a
     * RavenException.
     * 
     * @param req
     *            the request that requires authentication.
     * @param res
     *            the response to which to write the redirect instruction.
     * @param when
     *            the date to use for the expiry check.
     * @param msg
     *            text describing why authentication is being requested, or
     *            'null'. Passed to 'Request.msg'.
     * @return 'true' if the response has been written, or 'false' if the
     *         request requires further handling by the caller.
     * @throws RavenAuthenticationException
     *             if authentication fails.
     * @throws RavenException
     *             if there is a protocol error.
     */
    public boolean handleAuthentication(HttpServletRequest req,
	    HttpServletResponse res, Date when, String msg)
	    throws RavenException, IOException {
	if (!this.isTokenCurrent(when)) {
	    this.sendRedirectToRaven(req, res, msg);
	    return true;
	}
	try {
	    auth.validateTokenAgainstRequest(this.request, this.token);
	} catch (RavenException xoov) {
	    this.token = null;
	    throw xoov;
	}
	return false;
    }

    /**
     * Returns 'true' if 'this.getToken()' exists and has not expired by 'when'.
     */
    public boolean isTokenCurrent(Date when) {
	return this.token == null ? false : this.token.isCurrent(when);
    }

    /**
     * Returns 'true' if 'this.getToken()' exists and is valid. If you need more
     * detail in the case where 'this.getToken()' is not valid, use
     * 'checkTokenValid()' instead.
     */
    public boolean isTokenValid() {
	try {
	    auth.validateTokenAgainstRequest(this.request, this.token);
	    return true;
	} catch (RavenException xoov) {
	    return false;
	}
    }

    /**
     * Subclasses may override this method in order to micro-manage the data
     * sent in Raven authentication requests. It is applied to every
     * RavenAuthenticator.Request object, immediately after its construction.
     * The default implementation does nothing.
     */
    public void customiseRequest(Request rr, HttpServletRequest hsr) {
	// Do nothing!
    }

    /**
     * Returns the authentication token most recently received from the Raven
     * server.
     */
    public Token getToken() {
	return this.token;
    }

    /**
     * During the authentication protocol, a record of the URL that the user
     * originally requested. This is used purely for cosmetic purposes.
     */
    private String requestedURL = null;

    /** The Request most recently sent to the Raven server, or 'null'. */
    private Request request = null;

    /** The Token most recently received from the Raven server, or 'null'. */
    private Token token = null;

    /** The URL of the Raven server. */
    private final String ravenURL;

    /** The path recognised by 'interceptLoginPath()'. */
    private final String interceptLoginPath;

    /** A value for 'request.desc'. */
    private final String description;

    /**
     * Called by 'handleAuthentication()' when the user first tries to access a
     * resource that requires authentication. Constructs a Request object and
     * redirects to the Raven server.
     */
    private void sendRedirectToRaven(HttpServletRequest req,
	    HttpServletResponse res, String msg) throws IOException {
	// Take a copy of the requested URL for cosmetic purposes.
	final String pi = req.getPathInfo();
	this.requestedURL = new URL(req.getScheme(), req.getServerName(),
		req.getServerPort(), req.getContextPath()
			+ req.getServletPath() + (pi == null ? "" : pi))
		.toString();
	/*
	 * Or, if using an up-to-date servlet container:- this.requestedURL =
	 * req.getRequestURL().toString();
	 */
	final String query = req.getQueryString();
	if (query != null)
	    this.requestedURL += "?" + query;

	// Construct a Raven Request object.
	this.request = new Request(res.encodeRedirectURL(new URL(req
		.getScheme(), req.getServerName(), req.getServerPort(), req
		.getContextPath()
		+ req.getServletPath()
		+ this.interceptLoginPath).toString()));
	this.request.desc = this.description;
	this.request.msg = msg;
	this.customiseRequest(this.request, req);

	// Redirect to Raven.
	res.sendRedirect(this.ravenURL + "?" + this.request.toQString());
    }

}
