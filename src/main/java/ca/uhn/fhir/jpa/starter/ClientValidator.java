package ca.uhn.fhir.jpa.starter;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.security.oauth2.jwt.Jwt;

@Component
public class ClientValidator {
    public boolean isTrustedClient(Authentication authentication) {
        if (authentication instanceof JwtAuthenticationToken) {
            Jwt jwt = ((JwtAuthenticationToken) authentication).getToken();
            String clientId = jwt.getClaimAsString("azp");
            return "admin-client".equals(clientId);
        }
        return false;
    }
}
