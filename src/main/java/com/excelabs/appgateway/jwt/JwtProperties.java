package com.excelabs.appgateway.jwt;

import lombok.Data;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration("jwt")
public class JwtProperties {
    String headerName;
    boolean enableLogging;
    String tokenPrefix;
}
