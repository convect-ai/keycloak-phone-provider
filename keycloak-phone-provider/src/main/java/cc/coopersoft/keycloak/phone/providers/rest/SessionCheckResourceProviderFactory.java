package cc.coopersoft.keycloak.phone.providers.rest;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class SessionCheckResourceProviderFactory implements RealmResourceProviderFactory {

    public static final String ID = "session-check";

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new SessionCheckResourceProvider(session);
    }

    @Override
    public void init(org.keycloak.Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return ID;
    }
}
