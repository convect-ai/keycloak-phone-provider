package cc.coopersoft.keycloak.phone.providers.rest;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserSessionModel;
import org.keycloak.services.resource.RealmResourceProvider;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.*;

public class SessionCheckResourceProvider implements RealmResourceProvider {

    private KeycloakSession session;

    public SessionCheckResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return new SessionCheckEndpoint(session);
    }

    @Override
    public void close() {
    }

    public static class SessionCheckEndpoint {
        private KeycloakSession session;

        public SessionCheckEndpoint(KeycloakSession session) {
            this.session = session;
        }

        @GET
        @Path("check-session")
        @Produces(MediaType.APPLICATION_JSON)
        public Response checkSession(@Context HttpHeaders headers) {
            Cookie cookie = headers.getCookies().get("KEYCLOAK_SESSION");
            if (cookie == null) {
                return Response.status(Response.Status.UNAUTHORIZED).entity("No session cookie found").build();
            }

            String[] cookieParts = cookie.getValue().split("/");
            if (cookieParts.length < 3) {
                return Response.status(Response.Status.UNAUTHORIZED).entity("Invalid session cookie format").build();
            }

            String sessionId = cookieParts[2];

            UserSessionModel userSession = session.sessions().getUserSession(session.getContext().getRealm(), sessionId);
            if (userSession == null) {
                return Response.status(Response.Status.UNAUTHORIZED).entity("User session expired or invalid").build();
            }

            return Response.ok("User is logged in").build();
        }
    }
}
