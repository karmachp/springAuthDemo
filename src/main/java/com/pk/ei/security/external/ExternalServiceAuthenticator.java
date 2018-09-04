package com.pk.ei.security.external;

import com.pk.ei.security.AuthenticationWithToken;

public interface ExternalServiceAuthenticator {

    AuthenticationWithToken authenticate(String username, String password);
}
