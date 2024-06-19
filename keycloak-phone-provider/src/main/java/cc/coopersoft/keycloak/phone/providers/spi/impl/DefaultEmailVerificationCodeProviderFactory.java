package cc.coopersoft.keycloak.phone.providers.spi.impl;

import cc.coopersoft.keycloak.phone.providers.spi.EmailVerificationCodeProvider;
import cc.coopersoft.keycloak.phone.providers.spi.EmailVerificationCodeProviderFactory;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class DefaultEmailVerificationCodeProviderFactory implements EmailVerificationCodeProviderFactory {
    @Override
    public EmailVerificationCodeProvider create(KeycloakSession keycloakSession) {
        return new DefaultEmailVerificationCodeProvider(keycloakSession);
    }

    @Override
    public void init(Config.Scope scope) {

    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return "";
    }
}
