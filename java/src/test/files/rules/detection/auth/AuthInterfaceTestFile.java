import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.HttpServletRequest;
import java.security.Principal;

class AuthInterfaceTestFile {
    void useJwt() {
        Jwts.parser();
    }

    Principal usePrincipal(HttpServletRequest request) {
        return request.getUserPrincipal();
    }
}
