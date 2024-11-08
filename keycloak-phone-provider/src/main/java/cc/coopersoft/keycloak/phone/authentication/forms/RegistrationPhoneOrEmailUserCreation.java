package cc.coopersoft.keycloak.phone.authentication.forms;

import cc.coopersoft.keycloak.phone.Utils;
import cc.coopersoft.keycloak.phone.providers.constants.PhoneConstants;
import cc.coopersoft.keycloak.phone.providers.constants.TokenCodeType;
import cc.coopersoft.keycloak.phone.providers.exception.PhoneNumberInvalidException;
import cc.coopersoft.keycloak.phone.providers.representations.TokenCodeRepresentation;
import cc.coopersoft.keycloak.phone.providers.spi.EmailVerificationCodeProvider;
import cc.coopersoft.keycloak.phone.providers.spi.PhoneVerificationCodeProvider;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.authentication.forms.RegistrationPage;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.policy.PasswordPolicyManagerProvider;
import org.keycloak.policy.PolicyError;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.userprofile.UserProfile;
import org.keycloak.userprofile.UserProfileContext;
import org.keycloak.userprofile.UserProfileProvider;
import org.keycloak.userprofile.ValidationException;

import javax.ws.rs.core.MultivaluedMap;
import java.util.ArrayList;
import java.util.List;

import static cc.coopersoft.keycloak.phone.authentication.forms.SupportPhonePages.ATTEMPTED_PHONE_ACTIVATED;
import static cc.coopersoft.keycloak.phone.authentication.forms.SupportPhonePages.FIELD_PHONE_NUMBER;
import static cc.coopersoft.keycloak.phone.providers.constants.PhoneConstants.FIELD_EMAIL;

public class RegistrationPhoneOrEmailUserCreation implements FormActionFactory, FormAction {

    private static final Logger logger = Logger.getLogger(RegistrationPhoneOrEmailUserCreation.class);

    public static final String PROVIDER_ID = "registration-phone-email-creation";
    public static final String MISSING_PHONE_NUMBER_OR_EMAIL = "requiredPhoneNumberOrEmail";
    public static final String VERIFY_EMAIL_IMMEDIATELY = "verifyEmailImmediately";

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

    static {
        CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
                .property()
                .name(VERIFY_EMAIL_IMMEDIATELY)
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .label("Verify Email Immediately")
                .helpText("Enable to require immediate email verification during registration.")
                .defaultValue(true)
                .add()
                .build();
    }

    @Override
    public FormAction create(KeycloakSession session) {
        return this;
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
        return PROVIDER_ID;
    }

    @Override
    public void buildPage(FormContext context, LoginFormsProvider form) {
        logger.info("Now, building page for RegistrationPhoneOrEmailUserCreation");
        String credentialType = context.getSession().getAttribute(PhoneConstants.FIELD_CREDENTIAL_TYPE, String.class);
        if (credentialType != null && credentialType.equals(PhoneConstants.CREDENTIAL_TYPE_PHONE)) {
            logger.info("Building page for phone registration");
            form.setAttribute(ATTEMPTED_PHONE_ACTIVATED, true);
        } else {
            logger.info("Building page for email registration");
            // form.setAttribute(ATTEMPTED_PHONE_ACTIVATED, false);
        }
    }

    @Override
    public void validate(ValidationContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        List<FormMessage> errors = new ArrayList<>();
        context.getEvent().detail(Details.REGISTER_METHOD, "form");
        String phoneNumber = formData.getFirst(FIELD_PHONE_NUMBER);
        String email = formData.getFirst(FIELD_EMAIL);
        String credentialType = formData.getFirst(PhoneConstants.FIELD_CREDENTIAL_TYPE);
        context.getSession().setAttribute(PhoneConstants.FIELD_CREDENTIAL_TYPE, credentialType);
        String firstName = formData.getFirst(UserModel.FIRST_NAME);
        String lastName = formData.getFirst(UserModel.LAST_NAME);
        boolean success = true;

        // Validate first and last name fields
        if (Validation.isBlank(firstName)) {
            errors.add(new FormMessage(UserModel.FIRST_NAME, Messages.MISSING_FIRST_NAME));
            success = false;
        }
        if (Validation.isBlank(lastName)) {
            errors.add(new FormMessage(UserModel.LAST_NAME, Messages.MISSING_LAST_NAME));
            success = false;
        }

        if (credentialType.equals(PhoneConstants.CREDENTIAL_TYPE_PHONE)) {
            // Phone registration validation logic
            validatePhoneRegistration(context, formData, phoneNumber, errors);
        } else if (credentialType.equals(PhoneConstants.CREDENTIAL_TYPE_EMAIL)) {
            // Email registration validation logic
            validateEmailRegistration(context, formData, email, errors);
        } else {
            context.error(Errors.INVALID_INPUT);
            errors.add(new FormMessage(null, MISSING_PHONE_NUMBER_OR_EMAIL));
            success = false;
        }

        if (!errors.isEmpty() || !success) {
            logger.info("RegistrationPhoneOrEmailUserCreation: error");
            errors.forEach(error -> logger.info("Error: " + error.getMessage()));
            context.error(Errors.INVALID_REGISTRATION);
            formData.remove(RegistrationPage.FIELD_PASSWORD);
            formData.remove(RegistrationPage.FIELD_PASSWORD_CONFIRM);
            context.validationError(formData, errors);
        } else {
            logger.info("RegistrationPhoneOrEmailUserCreation: success");
            context.success();
        }
    }

    @Override
    public void success(FormContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String credentialType = formData.getFirst(PhoneConstants.FIELD_CREDENTIAL_TYPE);
        UserProfileProvider profileProvider = context.getSession().getProvider(UserProfileProvider.class);
        UserProfile profile = profileProvider.create(UserProfileContext.REGISTRATION_USER_CREATION, formData);
        UserModel user;

        // Handling based on credential type
        if (credentialType != null && credentialType.equals(PhoneConstants.CREDENTIAL_TYPE_PHONE)) {
            String phoneNumber;
            try {
                phoneNumber = Utils.canonicalizePhoneNumber(context.getSession(), formData.getFirst(FIELD_PHONE_NUMBER));
            } catch (PhoneNumberInvalidException e) {
                throw new RuntimeException(e);
            }
            formData.putSingle(UserModel.USERNAME, phoneNumber);
            context.getEvent().detail(Details.USERNAME, phoneNumber)
                    .detail(FIELD_PHONE_NUMBER, phoneNumber)
                    .detail(Details.REGISTER_METHOD, "phone");

            user = profile.create(); // Create the user with the phone number as username
            user.setSingleAttribute(PhoneConstants.FIELD_PHONE_NUMBER, phoneNumber);
            context.getSession().setAttribute(PhoneConstants.FIELD_PHONE_NUMBER, phoneNumber);
        } else if (credentialType != null && credentialType.equals(PhoneConstants.CREDENTIAL_TYPE_EMAIL)) {
            String email = formData.getFirst(FIELD_EMAIL);
            formData.putSingle(UserModel.USERNAME, email);
            context.getEvent().detail(Details.USERNAME, email)
                    .detail(FIELD_EMAIL, email)
                    .detail(Details.REGISTER_METHOD, "email");

            user = profile.create(); // Create the user with the email as username
            context.getSession().setAttribute(UserModel.EMAIL, email);

            // if not verify email immediately, set requiredActions to VERIFY_EMAIL
            if (!isVerifyEmailImmediately(context)) {
                // check if VerifyEmailByCode required action is already set
                if (Utils.isVerifyEmailByCodeRegistered(context.getSession())) {
                    user.addRequiredAction("VERIFY_EMAIL_CODE");
                } else {
                    user.addRequiredAction(UserModel.RequiredAction.VERIFY_EMAIL);
                }
            } else {
                user.setEmailVerified(true);
            }

            try {
                user.credentialManager().updateCredential(UserCredentialModel.password(formData.getFirst("password"), false));
            } catch (Exception me) {
                user.addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
            }

        } else {
            throw new IllegalStateException("Invalid registration method.");
        }

        // Finalize user setup
        user.setSingleAttribute("company", formData.getFirst("company"));
        user.setEnabled(true);
        context.setUser(user);
        context.getEvent().user(user);
        context.getEvent().success();
        context.getAuthenticationSession().setClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM, user.getUsername());
        context.newEvent().event(EventType.LOGIN);
        context.getEvent().client(context.getAuthenticationSession().getClient().getClientId())
                .detail(Details.REDIRECT_URI, context.getAuthenticationSession().getRedirectUri())
                .detail(Details.AUTH_METHOD, context.getAuthenticationSession().getProtocol());
        String authType = context.getAuthenticationSession().getAuthNote(Details.AUTH_TYPE);
        if (authType != null) {
            context.getEvent().detail(Details.AUTH_TYPE, authType);
        }
        try {
            String userId = user.getId();
            if (credentialType.equals(PhoneConstants.CREDENTIAL_TYPE_PHONE)) {
                String tokenCodeId = context.getSession().getAttribute(PhoneConstants.FIELD_TOKEN_ID, String.class);
                context.getSession().getProvider(PhoneVerificationCodeProvider.class).validateProcess(tokenCodeId, context.getUser());
            } else if (isVerifyEmailImmediately(context)) {
                String tokenCodeId = context.getSession().getAttribute(PhoneConstants.FIELD_TOKEN_ID, String.class);
                context.getSession().getProvider(EmailVerificationCodeProvider.class).validateProcess(tokenCodeId, context.getUser());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    // Methods for phone and email validation
    private void validatePhoneRegistration(ValidationContext context, MultivaluedMap<String, String> formData, String phoneNumber, List<FormMessage> errors) {
        KeycloakSession session = context.getSession();
        if (Validation.isBlank(phoneNumber)) {
            errors.add(new FormMessage(FIELD_PHONE_NUMBER, SupportPhonePages.Errors.MISSING.message()));
            context.error(Errors.INVALID_REGISTRATION);
            context.validationError(formData, errors);
        } else {
            try {
                phoneNumber = Utils.canonicalizePhoneNumber(session, phoneNumber);
                if (!Utils.isDuplicatePhoneAllowed(session) &&
                        Utils.findUserByPhone(session, context.getRealm(), phoneNumber).isPresent()) {
                    context.error(Errors.INVALID_REGISTRATION);
                    errors.add(new FormMessage(FIELD_PHONE_NUMBER, SupportPhonePages.Errors.EXISTS.message()));
                    context.validationError(formData, errors);
                }

            } catch (PhoneNumberInvalidException e) {
                context.error(Errors.INVALID_REGISTRATION);
                errors.add(new FormMessage(FIELD_PHONE_NUMBER, e.getErrorType().message()));
                context.validationError(formData, errors);
            }
        }

        String verificationCode = formData.getFirst(PhoneConstants.FIELD_VERIFICATION_CODE);
        logger.info(PhoneConstants.FIELD_VERIFICATION_CODE + ": " + verificationCode);
        TokenCodeRepresentation tokenCode;
        tokenCode = session.getProvider(PhoneVerificationCodeProvider.class).ongoingProcess(phoneNumber, TokenCodeType.REGISTRATION);
        if (tokenCode == null) {
            errors.add(new FormMessage(PhoneConstants.FIELD_VERIFICATION_CODE, PhoneConstants.SMS_CODE_MISMATCH));
            context.validationError(formData, errors);
        }
        if (Validation.isBlank(verificationCode) || tokenCode == null ||
                !tokenCode.getCode().equals(verificationCode)) {
            context.error(Errors.INVALID_CODE);
            context.getEvent().detail(PhoneConstants.FIELD_PHONE_NUMBER, phoneNumber);
            errors.add(new FormMessage(PhoneConstants.FIELD_VERIFICATION_CODE, PhoneConstants.SMS_CODE_MISMATCH));
            context.validationError(formData, errors);
        }

        if (tokenCode != null) {
            context.getSession().setAttribute(PhoneConstants.FIELD_TOKEN_ID, tokenCode.getId());
        }

        formData.remove(FIELD_EMAIL);
        context.getEvent().detail(FIELD_PHONE_NUMBER, phoneNumber);
        context.getEvent().detail(Details.USERNAME, phoneNumber);
        formData.putSingle(UserModel.USERNAME, phoneNumber);

        UserProfileProvider profileProvider = session.getProvider(UserProfileProvider.class);
        UserProfile profile = profileProvider.create(UserProfileContext.REGISTRATION_USER_CREATION, formData);

        String username = profile.getAttributes().getFirstValue(UserModel.USERNAME);
        context.getEvent().detail(Details.USERNAME, username);

        try {
            profile.validate();
        } catch (ValidationException pve) {
            pve.getErrors().forEach(error -> {
                logger.info("Validation error: " + error.getMessage());
            });
            triggerContextError(context, errors, pve);
        }
    }

    private void validateEmailRegistration(ValidationContext context, MultivaluedMap<String, String> formData, String email, List<FormMessage> errors) {
        KeycloakSession session = context.getSession();
        boolean verifyEmailImmediately = isVerifyEmailImmediately(context);

        if (Validation.isBlank(email)) {
            errors.add(new FormMessage(FIELD_EMAIL, Messages.MISSING_EMAIL));
        }
        formData.remove(PhoneConstants.FIELD_AREA_CODE);
        formData.remove(PhoneConstants.FIELD_PHONE_NUMBER);
        boolean emailValid = true;

        if (Validation.isBlank(email)) {
            errors.add(new FormMessage(RegistrationPage.FIELD_EMAIL, Messages.MISSING_EMAIL));
            emailValid = false;
        } else if (!Validation.isEmailValid(email)) {
            context.getEvent().detail(Details.EMAIL, email);
            errors.add(new FormMessage(RegistrationPage.FIELD_EMAIL, Messages.INVALID_EMAIL));
            emailValid = false;
        }

        if (emailValid && !context.getRealm().isDuplicateEmailsAllowed()) {
            boolean duplicateEmail = false;
            try {
                if (session.users().getUserByEmail(context.getRealm(), email) != null) {
                    duplicateEmail = true;
                }
            } catch (ModelDuplicateException e) {
                duplicateEmail = true;
            }
            if (duplicateEmail) {
                formData.remove(Validation.FIELD_EMAIL);
                context.getEvent().detail(Details.EMAIL, email);
                errors.add(new FormMessage(RegistrationPage.FIELD_EMAIL, Messages.EMAIL_EXISTS));
            }
        }

        if (Validation.isBlank(formData.getFirst(RegistrationPage.FIELD_PASSWORD))) {
            errors.add(new FormMessage(RegistrationPage.FIELD_PASSWORD, Messages.MISSING_PASSWORD));
        } else if (!formData.getFirst(RegistrationPage.FIELD_PASSWORD).equals(formData.getFirst(RegistrationPage.FIELD_PASSWORD_CONFIRM))) {
            errors.add(new FormMessage(RegistrationPage.FIELD_PASSWORD_CONFIRM, Messages.INVALID_PASSWORD_CONFIRM));
        }

        if (formData.getFirst(RegistrationPage.FIELD_PASSWORD) != null) {
            PolicyError err = context.getSession().getProvider(PasswordPolicyManagerProvider.class).validate(context.getRealm().isRegistrationEmailAsUsername() ? formData.getFirst(RegistrationPage.FIELD_EMAIL) : formData.getFirst(RegistrationPage.FIELD_USERNAME), formData.getFirst(RegistrationPage.FIELD_PASSWORD));
            if (err != null) {
                errors.add(new FormMessage(RegistrationPage.FIELD_PASSWORD, err.getMessage(), err.getParameters()));
            }
        }

        if (verifyEmailImmediately) {
            String verificationCode = formData.getFirst(PhoneConstants.FIELD_EMAIL_VERIFICATION_CODE);
            logger.info(PhoneConstants.FIELD_EMAIL_VERIFICATION_CODE + ": " + verificationCode);
            TokenCodeRepresentation tokenCode = session.getProvider(EmailVerificationCodeProvider.class).ongoingProcess(email, TokenCodeType.REGISTRATION);
            if (tokenCode == null) {
                logger.info("Token code is null");
                errors.add(new FormMessage(PhoneConstants.FIELD_EMAIL_VERIFICATION_CODE, PhoneConstants.VERIFICATION_CODE_MISMATCH));
                context.validationError(formData, errors);
            } else {
                logger.info(tokenCode.getCode());
            }
            if (Validation.isBlank(verificationCode) || tokenCode == null ||
                    !tokenCode.getCode().equals(verificationCode)) {
                context.error(Errors.INVALID_CODE);
                context.getEvent().detail(FIELD_EMAIL, email);
                errors.add(new FormMessage(PhoneConstants.FIELD_EMAIL_VERIFICATION_CODE, PhoneConstants.VERIFICATION_CODE_MISMATCH));
                context.validationError(formData, errors);
            }
            // set email verified to true
            if (tokenCode != null) {
                context.getSession().setAttribute(PhoneConstants.FIELD_TOKEN_ID, tokenCode.getId());
            }
        }

        context.getEvent().detail(Details.EMAIL, email);
        context.getEvent().detail(Details.USERNAME, email);
        formData.putSingle(UserModel.USERNAME, email);

        UserProfileProvider profileProvider = session.getProvider(UserProfileProvider.class);
        UserProfile profile = profileProvider.create(UserProfileContext.REGISTRATION_USER_CREATION, formData);

        String username = profile.getAttributes().getFirstValue(UserModel.USERNAME);
        context.getEvent().detail(Details.USERNAME, username);

        try {
            profile.validate();
        } catch (ValidationException pve) {
            pve.getErrors().forEach(error -> {
                logger.info("Validation error: " + error.getMessage());
            });
            triggerContextError(context, errors, pve);
        }
    }

    private void triggerContextError(ValidationContext context, List<FormMessage> errors, ValidationException pve) {
        if (pve.hasError(Messages.EMAIL_EXISTS)) {
            context.error(Errors.EMAIL_IN_USE);
        } else if (pve.hasError(Messages.MISSING_EMAIL, Messages.MISSING_USERNAME, Messages.INVALID_EMAIL)) {
            context.error(Errors.INVALID_REGISTRATION);
        } else if (pve.hasError(Messages.USERNAME_EXISTS)) {
            context.error(Errors.USERNAME_IN_USE);
        }
        errors.addAll(Validation.getFormErrorsFromValidation(pve.getErrors()));
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
        return "Registration Phone Or Email User Creation";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

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
        return "Create user with phone number or email";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    private boolean isVerifyEmailImmediately(FormContext context) {
        try {
            if (context.getAuthenticatorConfig() == null) {
                return true;
            } else {
                return "true".equalsIgnoreCase(context.getAuthenticatorConfig().getConfig()
                        .getOrDefault(VERIFY_EMAIL_IMMEDIATELY, "true"));
            }
        } catch (Exception e) {
            return true;
        }
    }

}
