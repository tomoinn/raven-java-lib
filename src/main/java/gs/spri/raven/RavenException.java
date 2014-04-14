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

/**
 * An Exception thrown by RavenAuthenticator to indicate unsuccessful
 * authentication.
 * 
 * @author Matthew Lavy and Alistair Turnbull
 * @version 1.0, 31 August 2005
 */
public class RavenException extends Exception {

    private static final long serialVersionUID = -7135272612559716224L;

    public RavenException() {
	super();
    }

    public RavenException(String msg) {
	super(msg);
    }
}
