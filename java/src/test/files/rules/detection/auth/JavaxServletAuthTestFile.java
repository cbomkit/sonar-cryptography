import java.security.Principal;
import javax.servlet.http.HttpServletRequest;

class JavaxServletAuthTestFile {
    String currentUser(HttpServletRequest request) {
        // Resolve the authenticated user through the legacy servlet namespace.
        Principal principal = request.getUserPrincipal(); // Auth: PRINCIPAL
        return principal == null ? "anonymous" : principal.getName();
    }

    String readApiKeyHeaderOnly(HttpServletRequest request) {
        // A header read is not authentication in the legacy API either.
        return request.getHeader("X-API-Key");
    }
}
