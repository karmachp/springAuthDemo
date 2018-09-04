package com.pk.ei.security.filter;

import java.io.IOException;
import java.util.Optional;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.util.UrlPathHelper;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pk.ei.api.APIController;
import com.pk.ei.security.AuthenticationWithToken;

public class AuthenticationFilter extends GenericFilterBean {

	private final static Logger logger = LoggerFactory.getLogger(AuthenticationFilter.class);
	public static final String TOKEN_SESSION_KEY = "token";
	public static final String USER_SESSION_KEY = "user";
	private AuthenticationManager authenticationManager;
    private String TOKEN_PREFIX = "Bearer ";

	public AuthenticationFilter(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}


	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		HttpServletRequest httpRequest = (HttpServletRequest)(request);
		HttpServletResponse httpResponse = (HttpServletResponse)(response);
		Optional<String> username = Optional.ofNullable(httpRequest.getHeader("Username"));
		Optional<String> password = Optional.ofNullable(httpRequest.getHeader("Password"));
		Optional<String> token = Optional.ofNullable(httpRequest.getHeader("Authorization"));

		String resourcePath = new UrlPathHelper().getPathWithinApplication(httpRequest);

		try {
			if (postToAuthenticate(httpRequest, resourcePath)) {
				logger.debug("Trying to authenticate user {} by X-Auth-Username method", username);
				processUsernamePasswordAuthentication(httpResponse, username, password);
				return;
			}

			if (token.isPresent()) {
				logger.debug("Trying to authenticate user by X-Auth-Token method. Token: {}", token);
				processTokenAuthentication(httpRequest, token);
			}

			logger.debug("AuthenticationFilter is passing request down the filter chain");
			addSessionContextToLogging();
			chain.doFilter(request, response);
		} catch (InternalAuthenticationServiceException internalAuthenticationServiceException) {
			SecurityContextHolder.clearContext();
			logger.error("Internal authentication service exception", internalAuthenticationServiceException);
			httpResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
		} catch (AuthenticationException authenticationException) {
			SecurityContextHolder.clearContext();
			httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, authenticationException.getMessage());
		} finally {
			MDC.remove(TOKEN_SESSION_KEY);
			MDC.remove(USER_SESSION_KEY);
		}
	}

	private void addSessionContextToLogging() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		String tokenValue = "EMPTY";
		if (authentication != null && !StringUtils.isEmpty(authentication.getDetails().toString())) {
			BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
			tokenValue = bCryptPasswordEncoder.encode(authentication.getDetails().toString());
		}
		MDC.put(TOKEN_SESSION_KEY, tokenValue);

		String userValue = "EMPTY";
		if (authentication != null && !StringUtils.isEmpty(authentication.getPrincipal().toString())) {
			userValue = authentication.getPrincipal().toString();
		}
		MDC.put(USER_SESSION_KEY, userValue);
	}

	private boolean postToAuthenticate(HttpServletRequest httpRequest, String resourcePath) {
		return APIController.AUTHENTICATE_URL.equalsIgnoreCase(resourcePath) && httpRequest.getMethod().equals("POST");
	}

	private void processUsernamePasswordAuthentication(HttpServletResponse httpResponse, Optional<String> username, Optional<String> password) throws IOException {
		Authentication resultOfAuthentication = tryToAuthenticateWithUsernameAndPassword(username, password);
		SecurityContextHolder.getContext().setAuthentication(resultOfAuthentication);
		httpResponse.setStatus(HttpServletResponse.SC_OK);
		
//		 JwtAuthenticationToken jwtAuthenticationToken = (JwtAuthenticationToken) authentication;
//		TokenResponse tokenResponse = new TokenResponse(resultOfAuthentication.getDetails().toString());
//		String tokenJsonResponse = new ObjectMapper().writeValueAsString(tokenResponse);
//		httpResponse.addHeader("Content-Type", "application/json");
//		httpResponse.getWriter().print(tokenJsonResponse);

		String respToken = TOKEN_PREFIX + resultOfAuthentication.getDetails().toString();
		String jwtResponse = new ObjectMapper().writeValueAsString(respToken);
//		httpResponse.addHeader(HEADER_STRING, respToken);
		httpResponse.setContentType("application/json");
		httpResponse.getWriter().write(jwtResponse);
	}

	private Authentication tryToAuthenticateWithUsernameAndPassword(Optional<String> username, Optional<String> password) {
		UsernamePasswordAuthenticationToken requestAuthentication = new UsernamePasswordAuthenticationToken(username, password);
		return tryToAuthenticate(requestAuthentication);
	}

	private void processTokenAuthentication(HttpServletRequest request, Optional<String> token) {
		AuthenticationWithToken resultOfAuthentication = tryToAuthenticateWithToken(token);
		resultOfAuthentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
		SecurityContextHolder.getContext().setAuthentication(resultOfAuthentication);
	}

	private AuthenticationWithToken tryToAuthenticateWithToken(Optional<String> token) {
//		PreAuthenticatedAuthenticationToken requestAuthentication = new PreAuthenticatedAuthenticationToken(token, null);
		AuthenticationWithToken requestAuthentication = new AuthenticationWithToken(token, null);
		return (AuthenticationWithToken) tryToAuthenticate(requestAuthentication);
	}

	private Authentication tryToAuthenticate(Authentication requestAuthentication) {
		Authentication responseAuthentication = authenticationManager.authenticate(requestAuthentication);
		if (responseAuthentication == null || !responseAuthentication.isAuthenticated()) {
			throw new InternalAuthenticationServiceException("Unable to authenticate Domain User for provided credentials");
		}
//		System.out.println("Authenticated."+responseAuthentication.getDetails());
		logger.debug("User successfully authenticated");
		return responseAuthentication;
	}

}
