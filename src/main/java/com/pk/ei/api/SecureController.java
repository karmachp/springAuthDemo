package com.pk.ei.api;

import java.util.Map;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController

public class SecureController {
	
	@RequestMapping("/user")
	@PreAuthorize("hasAuthority('ROLE_DOMAIN_USER')")
	public String welcome(Map<String, Object> model) {
		return "Secure controller";
	}

}
