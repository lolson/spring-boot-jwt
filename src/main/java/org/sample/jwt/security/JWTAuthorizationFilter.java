package org.sample.jwt.security;

import io.jsonwebtoken.Jwts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

import static org.sample.jwt.security.SecurityConstants.HEADER_STRING;
import static org.sample.jwt.security.SecurityConstants.TOKEN_PREFIX;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {
	private final Logger log = LoggerFactory.getLogger(JWTAuthorizationFilter.class);

	private KeyGenerator keyService;

	public JWTAuthorizationFilter(AuthenticationManager authenticationManager, KeyGenerator keyService) {
		super(authenticationManager);
		this.keyService = keyService;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request,
											HttpServletResponse response,
											FilterChain chain) throws  IOException, ServletException {
		String header = request.getHeader(HEADER_STRING);

		if(header == null || !header.startsWith(TOKEN_PREFIX)) {
			chain.doFilter(request, response);
			return;
		}

		UsernamePasswordAuthenticationToken authenticationToken = getAuthentication(request);
		SecurityContextHolder.getContext().setAuthentication(authenticationToken);
		chain.doFilter(request, response);
	}

	private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
		String token = request.getHeader(HEADER_STRING);
		if(token != null) {
			String user = Jwts.parser()
//					.setSigningKey(SECRET.getBytes())
					.setSigningKey(keyService.getPrivateKey())
					.parseClaimsJws(token.replace(TOKEN_PREFIX, ""))
					.getBody()
					.getSubject();
			log.info("Authorized user: "+user);
			if(user != null) {
				return new UsernamePasswordAuthenticationToken(user, null, new ArrayList<>());
			}
			return null;
		}
		return null;
	}
}
