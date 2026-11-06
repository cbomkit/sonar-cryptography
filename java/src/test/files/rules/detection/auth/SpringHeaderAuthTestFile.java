import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;

class SpringHeaderAuthTestFile {
    RequestHeaderAuthenticationFilter apiKeyFilter() {
        // Read the credential from the application's configured authentication header.
        RequestHeaderAuthenticationFilter filter = new RequestHeaderAuthenticationFilter(); // Auth: API_KEY
        filter.setPrincipalRequestHeader("X-API-Key");
        filter.setExceptionIfHeaderMissing(true);
        return filter;
    }
}
