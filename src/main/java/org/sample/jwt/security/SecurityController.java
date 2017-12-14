package org.sample.jwt.security;

import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import static org.sample.jwt.security.SecurityConstants.TOKEN_PREFIX;

@RestController
@RequestMapping("/token")
public class SecurityController {
	private final Logger log = LoggerFactory.getLogger(SecurityController.class);

	@Autowired
	private KeyGenerator keyService;

	@GetMapping("validate")
	public void validate(@RequestHeader String authorization)
	{
		String token = authorization.replace(TOKEN_PREFIX, "");
		// TODO: make REST call to get public key
		Jwt jwTok = null;
		try {
			jwTok = Jwts.parser().setSigningKey(keyService.getPublicKey()).parse(token);
		} catch(ExpiredJwtException eje) {
			log.error(eje.getMessage());
		} catch(MalformedJwtException mje) {
			log.error(mje.getMessage());
		} catch(SignatureException se) {
			log.error(se.getMessage());
		}
		if(jwTok != null) {
			log.info("Successfully parsed JWT: {}", jwTok);
		}
	}

	@ExceptionHandler(ExpiredJwtException.class)
	@ResponseStatus(HttpStatus.UNAUTHORIZED)
	public String handleExpiredJwtException(ExpiredJwtException eje) {
		return eje.getMessage();
	}

	@ExceptionHandler(MalformedJwtException.class)
	@ResponseStatus(HttpStatus.UNAUTHORIZED)
	public String handleMalformedJwtException(MalformedJwtException mje) {
		return mje.getMessage();
	}

	@ExceptionHandler(SignatureException.class)
	@ResponseStatus(HttpStatus.UNAUTHORIZED)
	public String handleSignatureException(SignatureException se) {
		return se.getMessage();
	}

}
