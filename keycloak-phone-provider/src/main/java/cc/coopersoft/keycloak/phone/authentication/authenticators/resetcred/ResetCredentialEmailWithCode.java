package cc.coopersoft.keycloak.phone.authentication.authenticators.resetcred;

import cc.coopersoft.keycloak.phone.authentication.forms.SupportPhonePages;
import cc.coopersoft.keycloak.phone.providers.constants.TokenCodeType;
import cc.coopersoft.keycloak.phone.providers.spi.EmailVerificationCodeProvider;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.*;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.events.EventType;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import java.util.List;

import static cc.coopersoft.keycloak.phone.authentication.forms.SupportPhonePages.*;
import cc.coopersoft.keycloak.phone.providers.constants.PhoneConstants;

public class ResetCredentialEmailWithCode implements Authenticator, AuthenticatorFactory {

    private static final Logger logger = Logger.getLogger(ResetCredentialEmailWithCode.class);

    public static final String PROVIDER_ID = "reset-credentials-email-with-code";
    public static final String FIELD_USERNAME = "username";
    public static final String FIELD_CODE = "code";
    public static final String FIELD_PASSWORD_CONFIRM = "password-confirm";
    public static final String FIELD_PASSWORD = "password";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        context.challenge(context.form().createPasswordReset());
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

        if (!validateForm(context, formData)) {
            context.clearUser();
            return;
        }
    }

    protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData) {
        EventBuilder event = context.getEvent();
        KeycloakSession session = context.getSession();
        String username = inputData.getFirst(FIELD_USERNAME);
        if (username == null || username.isEmpty()) {
            event.error(Errors.USERNAME_MISSING);
            Response challenge = context.form()
                    .addError(new FormMessage(FIELD_USERNAME, Messages.MISSING_USERNAME))
                    .createPasswordReset();
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, challenge);
            return false;
        }

        username = username.trim();

        RealmModel realm = context.getRealm();
        UserModel user = session.users().getUserByUsername(realm, username);
        if (user == null && realm.isLoginWithEmailAllowed() && username.contains("@")) {
            user =  session.users().getUserByEmail(realm, username);
        }

        context.getAuthenticationSession().setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, username);

        // we don't want people guessing usernames, so if there is a problem, just continue, but don't set the user
        // a null user will notify further executions, that this was a failure.
        if (user == null) {
            event.error(Errors.USER_NOT_FOUND);
            Response challenge = context.form()
                    .addError(new FormMessage(FIELD_USERNAME, Errors.USER_NOT_FOUND))
                    .createPasswordReset();
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, challenge);
            return false;
        } else if (!user.isEnabled()) {
            event.error(Errors.USER_DISABLED);
            Response challenge = context.form()
                    .addError(new FormMessage(FIELD_USERNAME, Errors.USER_DISABLED))
                    .createPasswordReset();
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, challenge);
            return false;
        }
        context.setUser(user);
        context.getEvent().user(user);

        String password = inputData.getFirst(FIELD_PASSWORD);
        String passwordConfirm = inputData.getFirst(FIELD_PASSWORD_CONFIRM);

        if (Validation.isBlank(password)) {
            context.getEvent().error(Errors.PASSWORD_MISSING);
            Response challenge = challenge(context, FIELD_PASSWORD, Messages.MISSING_PASSWORD, username);
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
            return false;
        } else if (!password.equals(passwordConfirm)) {
            context.getEvent().error(Errors.PASSWORD_CONFIRM_ERROR);
            Response challenge = challenge(context, FIELD_PASSWORD_CONFIRM, Messages.INVALID_PASSWORD_CONFIRM, username);
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
            return false;
        }

        String verificationCode = inputData.getFirst(FIELD_CODE);
        logger.info(FIELD_CODE + ": " + verificationCode);
        try {
            session.getProvider(EmailVerificationCodeProvider.class).validateCode(user, username, verificationCode, TokenCodeType.RESET);
            logger.info("verification code success!");
        } catch (Exception e) {
            logger.info("verification code fail!");
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            Response challenge = challenge(context, FIELD_CODE, SupportPhonePages.Errors.NOT_MATCH.message(), username);
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
            return false;
        }
        context.getUser().setEmailVerified(true);

        try {
            user.credentialManager().updateCredential(UserCredentialModel.password(password, false));
        } catch (ModelException me) {
            context.getEvent().error(Errors.PASSWORD_REJECTED);
            Response challenge = context.form()
                .addError(new FormMessage(FIELD_PASSWORD, me.getMessage(), me.getParameters()))
                .setAttribute(FIELD_USERNAME, username)
                .createPasswordReset();
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
            return false;
        } catch (Exception ape) {
            context.getEvent().error(Errors.PASSWORD_REJECTED);
            Response challenge = challenge(context, FIELD_PASSWORD, ape.getMessage(), username);
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
            return false;
        }

        context.getEvent().success();
        context.getAuthenticationSession().setClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM, username);
        context.newEvent().event(EventType.LOGIN);
        context.getEvent().client(context.getAuthenticationSession().getClient().getClientId())
                .detail(Details.REDIRECT_URI, context.getAuthenticationSession().getRedirectUri())
                .detail(Details.AUTH_METHOD, context.getAuthenticationSession().getProtocol());
        String authType = context.getAuthenticationSession().getAuthNote(Details.AUTH_TYPE);
        if (authType != null) {
            context.getEvent().detail(Details.AUTH_TYPE, authType);
        }
        context.forkWithSuccessMessage(new FormMessage("resetPasswordSuccess"));
        return true;
    }

    protected Response challenge(AuthenticationFlowContext context, String field, String message, String username) {
        return context.form()
            .addError(new FormMessage(field, message))
            .setAttribute(FIELD_USERNAME, username)
            .createPasswordReset();
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public String getDisplayType() {
        return "Reset Credential email with code";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED
    };

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Reset Credential email with code";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }

    @Override
    public void close() {

    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}