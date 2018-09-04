package com.pk.ei.api;

public class APIController {
	
	private static final String API_PATH = "/api/v1";

    public static final String AUTHENTICATE_URL = API_PATH + "/authenticate";

    // Spring Boot Actuator services
    public static final String MANAGEMENT_ENDPOINT = "/manage/info";
    public static final String AUTOCONFIG_ENDPOINT = "/autoconfig";
    public static final String BEANS_ENDPOINT = "/beans";
    public static final String CONFIGPROPS_ENDPOINT = "/configprops";
    public static final String ENV_ENDPOINT = "/env";
    public static final String MAPPINGS_ENDPOINT = "/mappings";
    public static final String METRICS_ENDPOINT = "/metrics";
    public static final String SHUTDOWN_ENDPOINT = "/shutdown";

}
