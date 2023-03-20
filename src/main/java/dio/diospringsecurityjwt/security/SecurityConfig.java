package dio.diospringsecurityjwt.security;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "security.config")
public class SecurityConfig {
    //existem propriedades no application.properties !!!!
    public static String PREFIX;
    public static String KEY; //-> Chave privada para criptografar
    public static Long EXPIRATION; //-> tempo de expiração

    public void setPrefix(String prefix){
        PREFIX = prefix;
    }

    public void setKey(String key) {
        KEY = key;
    }

    public void setExpiration(Long expiration){
        EXPIRATION = expiration;
    }

}
