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

import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.TimeZone;

/**
 * Utility functions used by other parts of the code, not intended to be of any use elsewhere.
 */
public abstract class Util {

    /** The format in which Raven expresses dates. */
    public static final DateFormat RAVEN_DATE_FORMAT = new SimpleDateFormat(
	    "yyyyMMdd'T'HHmmss'Z'");

    static {
	RAVEN_DATE_FORMAT.setTimeZone(TimeZone.getTimeZone("GMT+00:00"));
    }

    /**
     * URL encode the supplied string.
     * 
     * @param s
     * @return URLEncoded version of the string.
     */
    public static final String urlEncode(String s) {
	try {
	    return URLEncoder.encode(s, "UTF-8");
	} catch (UnsupportedEncodingException zoov) {
	    throw new RuntimeException("UTF-8 not supported. Apparently.");
	}
    }

    /**
     * Returns 's' with '%21' replaced by '!' and '%25' replaced by '%'.
     */
    public static final String decode(String s) {
	final StringBuffer ans = new StringBuffer();
	int pos = 0;
	while (true) {
	    int nextPercent = s.indexOf('%', pos);
	    if (nextPercent == -1 || nextPercent + 3 > s.length()) {
		return ans.append(s.substring(pos)).toString();
	    }
	    ans.append(s.substring(pos, nextPercent));
	    final String tc = s.substring(nextPercent, nextPercent + 3);
	    if ("%21".equals(tc)) {
		ans.append('!');
	    } else if ("%25".equals(tc)) {
		ans.append('%');
	    } else {
		ans.append(tc);
	    }
	    pos = nextPercent + 3;
	}
    }

    /**
     * A look-up table needed by 'decode64()'. Maps ASCII character codes to
     * 6-bit numbers.
     */
    public static final byte[] BASE64_VALUES = new byte[127];
    static {
	for (int i = 0; i < BASE64_VALUES.length; i++)
	    BASE64_VALUES[i] = (byte) 255;
	BASE64_VALUES[' '] = (byte) 254;
	BASE64_VALUES['\t'] = (byte) 254;
	BASE64_VALUES['\n'] = (byte) 254;
	BASE64_VALUES['\r'] = (byte) 254;
	for (char c = 'A'; c <= 'Z'; c++)
	    BASE64_VALUES[c] = (byte) (c - 'A');
	for (char c = 'a'; c <= 'z'; c++)
	    BASE64_VALUES[c] = (byte) (c - 'a' + 26);
	for (char c = '0'; c <= '9'; c++)
	    BASE64_VALUES[c] = (byte) (c - '0' + 52);
	BASE64_VALUES['-'] = 62;
	BASE64_VALUES['.'] = 63;
	BASE64_VALUES['_'] = 0;
    }

    /**
     * Raven-specific base-64-ish decoder.
     * 
     * @throws ParseException
     *             if 's' is not base64-ish-encoded data.
     */
    public static byte[] decode64(String s) throws ParseException {
	final ByteArrayOutputStream baos = new ByteArrayOutputStream();
	final char[] in = s.toCharArray();
	int pos = 0;
	while (true) {
	    while (pos < in.length && in[pos] == (byte) 254)
		pos++;
	    if (pos >= in.length)
		break;
	    int twentyFourBits = 0;
	    for (int i = 0; i < 4; i++) {
		if (pos >= in.length)
		    throw new ParseException("Data ended abruptly", pos);
		final byte sixBits = BASE64_VALUES[in[pos++]];
		if (sixBits == (byte) 255)
		    throw new ParseException("Bad character", pos);
		twentyFourBits = (twentyFourBits << 6) | sixBits;
	    }
	    if (in[pos - 4] == '_' || in[pos - 3] == '_')
		throw new ParseException("Data ended badly", pos - 4);
	    baos.write(twentyFourBits >>> 16);
	    if (in[pos - 2] == '_') {
		if (in[pos - 1] != '_')
		    throw new ParseException("Data ended badly", pos - 1);
		break;
	    } else {
		baos.write((twentyFourBits >>> 8) & 0xFF);
		if (in[pos - 1] == '_')
		    break;
		baos.write(twentyFourBits & 0xFF);
	    }
	}
	while (pos < in.length && in[pos] == (byte) 254)
	    pos++;
	if (pos < in.length)
	    throw new ParseException("Too much data", pos);
	return baos.toByteArray();
    }

}
