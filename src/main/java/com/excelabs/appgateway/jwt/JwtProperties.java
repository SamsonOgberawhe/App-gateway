package com.excelabs.appgateway.jwt;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "security.jwt")
public class JwtProperties {
    String headerName;
    boolean enableLogging;
    String tokenPrefix;
    private String publicKey;
    private long expirationMs;
    private String issuer;
}
