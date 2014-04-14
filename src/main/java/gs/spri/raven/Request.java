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

import java.util.Date;
import java.util.HashSet;
import java.util.Set;

/**
 * Encapsulates all of the data sent to Raven in an Authentication Request.
 * <p>
 * Documentation of fields consists of a paragraph directly lifted from the <a
 * href="http://raven.cam.ac.uk/project/waa2wls-protocol.txt">WAA2WLS Protocol
 * specification</a>, followed by our own Java-specific comments where required.
 * We have omitted the deprecated 'skew' parameter.
 */
public class Request {
    /**
     * Constructs a Request, given values for those fields which are "REQUIRED".
     * 
     * @param url
     *            a value for the 'url' field.
     */
    public Request(String url) {
	this.url = url;
	this.aauth.add("pwd");
    }

    /**
     * [REQUIRED] The version of the WLS protocol in use. This document
     * describes version 1 of the protocol.
     * <p>
     * Value is fixed as "1".
     */
    public final String ver = "1";

    /**
     * [REQUIRED] A fully-qualified http or https URL. On completion of the
     * authentication process this URL will be used to compose an
     * 'authentication response message' and to return this to the WAA. The URL
     * may be displayed to the end-user to help identify the resource to which
     * his/her identity is being disclosed.
     * <p>
     * This must be passed to the constructor.
     */
    public final String url;

    /**
     * A text description of the resource requesting authentication which may be
     * displayed to the end-user to further identify the resource to which
     * his/her identity is being disclosed. This data is restricted to printable
     * ASCII characters (0x20 - 0x7e) [ANSI-X3.4-1986] though it may contain
     * HTML character or numeric entities representing other characters. The
     * characters '&lt;' and '&gt;' will be converted into HTML entities before
     * being sent to the browser and as a result this text can not contain HTML
     * markup.
     * <p>
     * Default value = null.
     */
    public String desc = null;

    /**
     * [OPTIONAL] A text string representing the types of authentication that
     * will satisfy this request. This value consists of a sequence of text
     * tokens separated by ',' as described below. The default value, if the
     * parameter is omitted or empty, is not specified but will always consist
     * of at least one type of authentication that is at least as secure as
     * username/password.
     * <p>
     * The Default value is the one type of authentication currently supported:
     * "pwd". 'null' indicates that this field is absent.
     */
    public Set<String> aauth = new HashSet<String>();

    /**
     * [OPTIONAL] A text token. The value 'yes' requires that a
     * re-authentication exchange takes place with the user. This could be used
     * prior to a sensitive transaction in an attempt to ensure that a
     * previously authenticated user is still present at the browser. The value
     * 'no' requires that the authentication request will only succeed if the
     * user's identity can be returned without interacting with the user. This
     * could be used as an optimisation to take advantage of any existing
     * authentication but without actively soliciting one. If omitted or empty,
     * then a previously established identity may be returned if the WLS
     * supports doing so, and if not then the user will be prompted as
     * necessary.
     * <p>
     * The default value is 'null' which means "omitted or empty". The value
     * 'Boolean.TRUE' means "yes" and 'Boolean.FALSE' means "no".
     */
    public Boolean iact = null;

    /**
     * [OPTIONAL] Text describing why authentication is being requested on this
     * occasion which may be displayed to the end-user. This could be used, for
     * example, to explain that re-authentication is being requested following
     * an error condition in the WAA. This data is subject to the same
     * constraints as that in 'desc'.
     * <p>
     * Default value is 'null'.
     */
    public String msg = null;

    /**
     * [OPTIONAL] Data that will be returned unaltered to the WAA in any
     * 'authentication response message' issued as a result of this request.
     * This could be used to carry the identity of the resource originally
     * requested or other WAA state, or to associate authentication requests
     * with their eventual replies. When returned, this data will be protected
     * by the digital signature applied to the authentication response message
     * but nothing else is done to ensure the integrity or confidentiality of
     * this data - the WAA MUST take responsibility for this if necessary.
     * <p>
     * Default value is 'null'.
     */
    public String params = null;

    /**
     * [OPTIONAL] The current date and time according to the WAA. This parameter
     * was used in conjunction with the now deprecated 'skew' parameter but is
     * retained because it can provide valuable debugging information when
     * investigating problems cause by skew between the clocks used by the WAA
     * and the WLS.
     * <p>
     * This can be converted to the format required by Raven using
     * 'encodeDate()' and back again using 'decodeDate()'. Default value = 'new
     * Date()'.
     */
    public final Date date = new Date();

    /**
     * [OPTIONAL] A text token. If this parameter is 'yes' and the outcome of
     * the request is anything other than success (i.e. the status code would be
     * anything other than 200) then the WLS MUST return an informative error to
     * the user and MUST not redirect back to the WAA. Setting this makes it
     * easier to implement WAAs at the expense of a loss of flexibility in error
     * handling.
     * <p>
     * 'true' means 'yes'. Default value = 'false'.
     */
    public boolean fail = false;

    /**
     * Converts this Request into a String suitable for use as the query string
     * component of a URL.
     */
    public String toQString() {
	final StringBuffer ans = new StringBuffer();
	ans.append("ver=").append(Util.urlEncode(this.ver));
	ans.append("&").append("url=").append(Util.urlEncode(this.url));
	if (this.desc != null)
	    ans.append("&").append("desc=").append(Util.urlEncode(this.desc));
	if (this.aauth != null) {
	    ans.append("&").append("aauth=");
	    String sep = "";
	    for (String s : this.aauth) {
		ans.append(sep).append(s);
		sep = ",";
	    }
	}
	if (this.iact != null) {
	    ans.append("&").append("iact=");
	    ans.append(this.iact.booleanValue() ? "yes" : "no");
	}
	if (this.msg != null)
	    ans.append("&").append("msg=").append(Util.urlEncode(this.msg));
	if (this.params != null)
	    ans.append("&").append("params=")
		    .append(Util.urlEncode(this.params));
	if (this.date != null) {
	    ans.append("&").append("date=");
	    ans.append(Util.urlEncode(Util.RAVEN_DATE_FORMAT
		    .format(this.date)));
	}
	if (this.fail)
	    ans.append("&").append("fail=yes");
	return ans.toString();
    }

}