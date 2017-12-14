package org.sample.jwt.security;

/**
 * Created by leif on 12/12/17.
 */
public class SecurityConstants {
	public static final long EXPIRATION_TIME = 864_000_000; //10 days
//	public static final long EXPIRATION_TIME = 300_000; //5 min
//	public static final long EXPIRATION_TIME = 60_000; //1 min
	public static final String TOKEN_PREFIX = "Bearer ";
	public static final String HEADER_STRING ="Authorization";
	public static final String SIGN_UP_URL= "/users/sign-up";
}
