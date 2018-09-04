package com.pk.ei.security.provider;

import java.util.Optional;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import com.pk.ei.security.AuthenticationWithToken;
import com.pk.ei.security.JwtTokenService;
import com.pk.ei.security.TokenService;

public class TokenAuthenticationProvider implements AuthenticationProvider {

    private JwtTokenService tokenService;

    public TokenAuthenticationProvider(TokenService tokenService) {
        this.tokenService = (JwtTokenService) tokenService;
    }

   /* @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Optional<String> token = (Optional) authentication.getPrincipal();
        System.out.println("Inside token auth provider"+token);
        if (!token.isPresent() || token.get().isEmpty()) {
            throw new BadCredentialsException("Invalid token");
        }
        if (!tokenService.contains(token.get())) {
            throw new BadCredentialsException("Invalid token or token expired");
        }
        return tokenService.retrieve(token.get());
    }*/
    
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    	Optional<String> token = (Optional) authentication.getPrincipal();
//    	System.out.println("Inside token auth provider. Token: "+token);
    	if(token.isPresent() && token.get().startsWith("Bearer ")){
        	String authToken = token.get().substring(7);
        	if(tokenService.validateToken(authToken))
        		return tokenService.retrieve(authToken);
        }
        throw new BadCredentialsException("Invalid token or token expired");
    }
    
    

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(AuthenticationWithToken.class);
    }
}
