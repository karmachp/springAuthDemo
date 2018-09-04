package com.pk.ei.api;

import java.util.Map;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

	@RequestMapping("/")
	public String welcome(Map<String, Object> model) {
		return "Home controller";
	}
	
	@RequestMapping("/public/test")
	public String openToPublic(Map<String, Object> model) {
		return "Public access controller";
	}

	
	
}
