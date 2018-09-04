package com.pk.ei.security;

import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.pk.ei.security.external.ExternalServiceAuthenticator;
import com.pk.ei.security.external.SomeExternalServiceAuthenticator;
import com.pk.ei.security.filter.AuthenticationFilter;
import com.pk.ei.security.filter.ManagementEndpointAuthenticationFilter;
import com.pk.ei.security.provider.BackendAdminUsernamePasswordAuthenticationProvider;
import com.pk.ei.security.provider.DomainUsernamePasswordAuthenticationProvider;
import com.pk.ei.security.provider.TokenAuthenticationProvider;

@Configuration
@EnableWebSecurity 
@EnableScheduling
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Override
	public void configure(WebSecurity web) throws Exception {
	    web.ignoring().antMatchers("/public/*");
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
	    http.
	            csrf().disable().
	            sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).
	            and().
	            authorizeRequests().
	            antMatchers("/").permitAll().
	            antMatchers("/manage/*").hasRole("BACKEND_ADMIN").
	            anyRequest().authenticated().
	            and().
	            anonymous().disable().
	            exceptionHandling().authenticationEntryPoint(unauthorizedEntryPoint());

	    http.addFilterBefore(new AuthenticationFilter(authenticationManager()), BasicAuthenticationFilter.class).
	            addFilterBefore(new ManagementEndpointAuthenticationFilter(authenticationManager()), BasicAuthenticationFilter.class);
	}
	
	@Bean
	public AuthenticationEntryPoint unauthorizedEntryPoint() {
	    return (request, response, authException) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	    auth.authenticationProvider(domainUsernamePasswordAuthenticationProvider()).
	            authenticationProvider(backendAdminUsernamePasswordAuthenticationProvider()).
	            authenticationProvider(tokenAuthenticationProvider());
	}
	
	@Bean
    public TokenService tokenService() {
        return new JwtTokenService();
    }

    @Bean
    public ExternalServiceAuthenticator someExternalServiceAuthenticator() {
        return new SomeExternalServiceAuthenticator();
    }

    @Bean
    public AuthenticationProvider domainUsernamePasswordAuthenticationProvider() {
        return new DomainUsernamePasswordAuthenticationProvider(tokenService(), someExternalServiceAuthenticator());
    }

    @Bean
    public AuthenticationProvider backendAdminUsernamePasswordAuthenticationProvider() {
        return new BackendAdminUsernamePasswordAuthenticationProvider();
    }

    @Bean
    public AuthenticationProvider tokenAuthenticationProvider() {
        return new TokenAuthenticationProvider(tokenService());
    }

	
}