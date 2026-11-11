import org.pac4j.core.credentials.authenticator.Authenticator;
import org.pac4j.http.client.direct.HeaderClient;
import org.pac4j.http.client.direct.ParameterClient;

class Pac4jApiKeyAuthTestFile {
    HeaderClient headerApiKey(Authenticator authenticator) {
        // Validate credentials supplied in the API-key header.
        return new HeaderClient("X-API-Key", authenticator); // Auth: API_KEY
    }

    ParameterClient parameterApiKey(Authenticator authenticator) {
        // Support an application that receives the credential as a request parameter.
        return new ParameterClient("api_key", authenticator); // Auth: API_KEY
    }
}
