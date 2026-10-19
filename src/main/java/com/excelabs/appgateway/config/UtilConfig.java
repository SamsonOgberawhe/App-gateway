package com.excelabs.appgateway.config;

import com.excelabs.appgateway.jwt.JwtProperties;
import com.excelabs.appgateway.jwt.JwtUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class UtilConfig {
    @Bean
    public JwtUtil jwtUtil(JwtProperties properties) {
        return new JwtUtil(
                properties.getPublicKey(),
                properties.getExpirationMs(),
                properties.getIssuer()
        );
    }

}
