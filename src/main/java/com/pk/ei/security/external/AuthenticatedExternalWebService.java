package com.pk.ei.security.external;

import org.springframework.security.core.GrantedAuthority;

import com.pk.ei.security.AuthenticationWithToken;

import java.util.Collection;

public class AuthenticatedExternalWebService extends AuthenticationWithToken {

//    private ExternalWebServiceStub externalWebService;

    /**
	 * 
	 */
	private static final long serialVersionUID = -1647781310532850719L;

	public AuthenticatedExternalWebService(Object aPrincipal, Object aCredentials, Collection<? extends GrantedAuthority> anAuthorities) {
        super(aPrincipal, aCredentials, anAuthorities);
    }

/*    public void setExternalWebService(ExternalWebServiceStub externalWebService) {
        this.externalWebService = externalWebService;
    }

    public ExternalWebServiceStub getExternalWebService() {
        return externalWebService;
    }*/
}
