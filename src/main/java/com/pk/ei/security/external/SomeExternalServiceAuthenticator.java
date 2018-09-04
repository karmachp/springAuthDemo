package com.pk.ei.security.external;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.authority.AuthorityUtils;
import com.pk.ei.domain.DomainUser;

public class SomeExternalServiceAuthenticator implements ExternalServiceAuthenticator {
	
	@Value("${ws.auth.url}")
    private String wsAuthURL;
	
	@Value("${ws.auth.domain}")
    private String wsAuthDomain;
	
	@Value("${ws.auth.description}")
    private String wsAuthDescription;
	

    @Override
    public AuthenticatedExternalWebService authenticate(String username, String password) {
//        ExternalWebServiceStub externalWebService = new ExternalWebServiceStub();

        // External WS Authentication
        if(!"ext_admin".equals(username))
        	throw new BadCredentialsException("Invalid username");
        
        /*
        RestTemplate restTemplate = new RestTemplate();
		String url = wsAuthURL+"/"+username+"/"+password+"/";
		System.out.println("Request: "+url);
		ResponseEntity<String> response	= restTemplate.getForEntity(url, String.class);
		System.out.println("response status: "+response.getStatusCodeValue());
		if(!response.getStatusCode().equals(HttpStatus.OK))
			throw new BadCredentialsException("Authentcation failed");*/
        
		// ...
        // ...

        // Create authenticated wrapper with Principal and GrantedAuthorities.
        AuthenticatedExternalWebService authenticatedExternalWebService = new AuthenticatedExternalWebService(new DomainUser(username), null,
                AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_DOMAIN_USER, ROLE_WEB_USER"));
//        authenticatedExternalWebService.setExternalWebService(externalWebService);

        return authenticatedExternalWebService;
    }
}
