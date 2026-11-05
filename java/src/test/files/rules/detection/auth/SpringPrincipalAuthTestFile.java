import org.springframework.security.core.Authentication;

class SpringPrincipalAuthTestFile {
    Object currentUser(Authentication authentication) {
        return authentication.getPrincipal(); // Auth: PRINCIPAL
    }
}
