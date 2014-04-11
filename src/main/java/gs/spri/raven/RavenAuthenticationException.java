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

/**
 * A RavenException that is thrown because Raven reported an authentication
 * failure, i.e. a status code other than '200'. The code returned is stored in
 * the 'status' field.
 * 
 * @author Matthew Lavy and Alistair Turnbull
 * @version 1.0, 31 August 2005
 */
public class RavenAuthenticationException extends RavenException {

	private static final long serialVersionUID = 1085961263625640521L;

	public RavenAuthenticationException(int status) {
		super();
		this.status = status;
	}

	public RavenAuthenticationException(String msg, int status) {
		super(msg);
		this.status = status;
	}

	/**
	 * The status code returned by Raven, as defined by the WLS-WAA protocol
	 * specification.
	 */
	public final int status;

	/** Returns a human-readable interpretation of the status code. */
	public String getStatusString() {
		switch (this.status) {
		case 200:
			return "Successfull authentication";
		case 410:
			return "The user cancelled the authentication request";
		case 510:
			return "No mutually acceptable authentication types available";
		case 520:
			return "Unsupported protocol exception";
		case 530:
			return "General request parameter error";
		case 540:
			return "Interaction would be required";
		case 560:
			return "WAA not authorised";
		case 570:
			return "Authentication declined";
		default:
			return "Unknown status code: " + this.status;
		}
	}
}
