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

import gs.spri.raven.core.RavenException;
import gs.spri.raven.core.RavenStateException;
import gs.spri.raven.core.Token;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * RavenServlet is the shell of a complete web application. It's purpose is to
 * handle the control flow aspects of the Raven authentication protocol. It has
 * inner classes Action and MapAction, which represent at different levels of
 * abstraction a request for a possibly Raven-protected resource.
 * <p>
 * The shortest path to a working Java servlet that authenticates against Raven
 * is to write a subclass of RavenServlet. The alternative is to go down a
 * level, and use the API on top of which RavenServlet is implemented, namely
 * the class RavenAuthenticator.
 * 
 * @author Matthew Lavy and Alistair Turnbull
 * @version 1.0.3, 02 August 2007
 */
public abstract class RavenServlet extends HttpServlet {

    private static final long serialVersionUID = -8095474748680351346L;

    /**
     * Returns the identifier of the logged in principal associated with 'ses',
     * or 'null'.
     */
    public String getUserName(HttpSession ses) {
	final Token tok = this.getToken(ses);
	if (tok == null)
	    return null;
	return tok.principal;
    }

    /**
     * Returns the authentication token associated with 'ses' or 'null'.
     */
    public Token getToken(HttpSession ses) {
	if (ses == null)
	    return null;
	final SessionObject so = (SessionObject) ses.getAttribute(SESSION_KEY);
	if (so == null)
	    return null;
	return so.ra.getToken();
    }

    /* HTTPSERVLET OVERRIDES */

    /**
     * Initialises this RavenServlet. Called by the servlet container when a
     * servlet starts up. If subclasses override this method, they MUST call
     * 'super.init(config)'.
     * <p>
     * 
     */
    public void init(ServletConfig config) throws ServletException {
	super.init(config);
	this.ravenURL = config.getInitParameter(CONF_PREFIX + "raven-url");
	this.interceptLoginPath = config.getInitParameter(CONF_PREFIX
		+ "intercept-login-path");
	this.keyPrefix = config.getInitParameter(CONF_PREFIX + "key-prefix");
	this.description = config.getInitParameter(CONF_PREFIX + "description");
	try {
	    this.keyStore = KeyStore.getInstance("JKS");
	    final String filename = config.getInitParameter(CONF_PREFIX
		    + "keystore");
	    final String password = config.getInitParameter(CONF_PREFIX
		    + "keystore-password");
	    final InputStream is = new FileInputStream(filename);
	    this.keyStore.load(is, password.toCharArray());
	    is.close();
	} catch (KeyStoreException xoov) {
	    throw new ServletException("Cannot construct keystore", xoov);
	} catch (IOException xoov) {
	    throw new ServletException("Cannot load certificate file", xoov);
	} catch (NoSuchAlgorithmException xoov) {
	    throw new ServletException("Cannot understand cert file", xoov);
	} catch (CertificateException xoov) {
	    throw new ServletException("Cannot understand cert file", xoov);
	}
    }

    protected final void doGet(HttpServletRequest req, HttpServletResponse res)
	    throws IOException, ServletException {
	this.doPost(req, res);
    }

    protected final void doPost(HttpServletRequest req, HttpServletResponse res)
	    throws IOException, ServletException {
	// Get a RavenAuthenticator
	final HttpSession ses = req.getSession(true);
	SessionObject so = (SessionObject) ses.getAttribute(SESSION_KEY);
	if (so == null) {
	    so = new SessionObject();
	    so.ra = new RavenAuthenticator(this.ravenURL,
		    this.interceptLoginPath, this.description, this.keyStore,
		    this.keyPrefix);
	    ses.setAttribute(SESSION_KEY, so);
	}
	Action a = null;
	try {
	    a = so.action;
	    if (so.ra.interceptLoginRequest(req, res))
		return;
	    so.action = null;
	    if (a == null)
		a = this.parseRequest(req);
	    if (this.requiresAuthentication(a)) {
		if (so.ra.handleAuthentication(req, res, new Date(), null)) {
		    so.action = a;
		    return;
		}
	    }
	    this.performAction(a, ses, res);
	} catch (RavenAuthenticationException xoov) {
	    this.reportRavenAuthenticationException(a, res, xoov);
	} catch (RavenStateException xoov) {
	    this.reportRavenStateException(a, res, xoov);
	} catch (RavenException xoov) {
	    this.reportRavenException(a, res, xoov);
	} catch (ServletException xoov) {
	    this.reportServletException(a, res, xoov);
	}
    }

    /**
     * Extracts from 'req' all information necessary for processing the request.
     * This method can be called before the user is authenticated. The Action
     * returned should contain no reference to 'req'. Subclasses must not assume
     * that the Action will be passed to 'performAction()' immediately or at
     * all; it may be delayed by several request/response cycles. The method
     * should therefore not have any side-effects.
     * <p>
     * The default implementation puts all the HTTP parameters into a MapAction.
     * 
     * @param req
     *            the HttpServletRequest to parse.
     * @return an Action.
     */
    protected Action parseRequest(HttpServletRequest req) throws IOException,
	    ServletException {
	final Map<String, String> params = new HashMap<String, String>();
	for (Enumeration<String> e = req.getParameterNames(); e
		.hasMoreElements();) {
	    final String name = (String) e.nextElement();
	    final String value = req.getParameter(name);
	    params.put(name, value);
	}
	return new MapAction(req.getPathInfo(), params);
    }

    /**
     * Returns 'true' if 'a' requires authentication. Otherwise returns 'false'.
     * The default implementation always returns 'true'. Subclasses can override
     * this to provide finer-grained control of access to resources.
     * 
     * @param a
     *            the Action to test.
     */
    protected boolean requiresAuthentication(Action a) throws ServletException {
	return true;
    }

    /**
     * Performs the specified Action and writes an appropriate response to
     * 'res'. This method will only be called after the user is authenticated or
     * if the Action does not require authentication. This method may have
     * side-effects.
     * 
     * @param a
     *            the Action to perform.
     * @param ses
     *            the HttpSession.
     * @param res
     *            the HttpServletResponse to which to write.
     */
    protected abstract void performAction(Action a, HttpSession ses,
	    HttpServletResponse res) throws IOException, ServletException;

    /**
     * Called when authentication is not possible because a user could not be
     * authenticated. The default implementation sends an error 401 to the
     * browser.
     * 
     * @param action
     *            the Action that would have been called had authentication
     *            succeeded. The Action will be discarded after this method is
     *            called.
     * @param res
     *            the HttpServletResponse to which to write.
     * @param cause
     *            the RavenException describing the error.
     */
    protected void reportRavenAuthenticationException(Action action,
	    HttpServletResponse res, RavenAuthenticationException cause)
	    throws IOException, ServletException {
	final String statusString = cause.status + ": "
		+ cause.getStatusString();
	res.sendError(HttpServletResponse.SC_UNAUTHORIZED, statusString + " ("
		+ cause.getMessage() + ")");
    }

    /**
     * Called when a token is received from Raven before the application has
     * requested one. This can happen for example if a user bookmarks the Raven
     * login page. The default implementation discards the useless token and
     * redirects the browser to the root URL of the server (i.e. "/").
     * 
     * @param action
     *            the Action that would have been called had authentication
     *            succeeded. The Action will be discarded after this method is
     *            called.
     * @param res
     *            the HttpServletResponse to which to write.
     * @param cause
     *            the RavenException describing the error.
     */
    protected void reportRavenStateException(Action action,
	    HttpServletResponse res, RavenStateException cause)
	    throws IOException, ServletException {
	res.sendRedirect("/");
    }

    /**
     * Called when authentication is not possible because of a protocol error.
     * The default implementation sends an error 500 to the browser.
     * 
     * @param action
     *            the Action that would have been called had authentication
     *            succeeded. The Action will be discarded after this method is
     *            called.
     * @param res
     *            the HttpServletResponse to which to write.
     * @param cause
     *            the RavenException describing the error.
     */
    protected void reportRavenException(Action action, HttpServletResponse res,
	    RavenException cause) throws IOException, ServletException {
	res.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
		cause.getMessage());
    }

    /**
     * Called when a ServletException is thrown. The default implementation
     * sends an error 500 to the browser.
     * 
     * @param action
     *            the Action that would have been called had no Exception been
     *            thrown. Action will be discarded after this method is called.
     * @param res
     *            the HttpServletResponse to which to write.
     * @param cause
     *            the RavenException describing the error.
     */
    protected void reportServletException(Action action,
	    HttpServletResponse res, ServletException cause)
	    throws IOException, ServletException {
	res.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
		cause.getMessage());
    }

    /**
     * The abstract super-class of actions that a web client may ask this
     * RavenServlet to perform. Instances of Action are constructed by the
     * 'parseRequest()' method, and are performed by the 'performAction()'
     * method. Subclasses must not assume that an Action will be passed to
     * 'performAction()' immediately after construction or at all; it may be
     * delayed by several request/response cycles.
     */
    public static abstract class Action {
    }

    /**
     * An Action containing a Map of all the HTTP parameters from a request.
     */
    public static class MapAction extends Action {
	/** Constructs a MapAction, given values for its fields. */
	public MapAction(String pathInfo, Map<String, String> params) {
	    this.pathInfo = pathInfo;
	    this.params = params;
	}

	/**
	 * The requested path, relative to the servlet root. This is the string
	 * returned by 'HttpServletRequest.getPathInfo()'.
	 */
	public final String pathInfo;

	/**
	 * All the HTTP parameters from a request. Keys are Strings (parameter
	 * names); Values are Strings (parameter values).
	 */
	public final Map<String, String> params;
    }

    /** The key used to retrieve the RavenAuthenticator from an HttpSession. */
    public static final String SESSION_KEY = "Igneousrocksarebetterthansedimentaryones.Applepieisbetterthanplum35";

    /**
     * The prefix for all RavenServlet configuration parameters in web.xml.
     */
    public static final String CONF_PREFIX = "gs.spri.raven.";

    /* PRIVATE */

    private String ravenURL = null;
    private String interceptLoginPath = null;
    private String description = null;
    private String keyPrefix = null;
    private KeyStore keyStore = null;

    /**
     * Wraps a RavenAuthenticator and an Action to put in a session.
     */
    private static class SessionObject {
	public RavenAuthenticator ra = null;
	public Action action = null;
    }
}
