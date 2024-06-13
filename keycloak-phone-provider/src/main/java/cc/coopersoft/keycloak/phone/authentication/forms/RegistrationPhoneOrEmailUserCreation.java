package cc.coopersoft.keycloak.phone.authentication.forms;

import cc.coopersoft.keycloak.phone.Utils;
import cc.coopersoft.keycloak.phone.providers.constants.PhoneConstants;
import cc.coopersoft.keycloak.phone.providers.constants.TokenCodeType;
import cc.coopersoft.keycloak.phone.providers.exception.PhoneNumberInvalidException;
import cc.coopersoft.keycloak.phone.providers.representations.TokenCodeRepresentation;
import cc.coopersoft.keycloak.phone.providers.spi.PhoneVerificationCodeProvider;
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

import static cc.coopersoft.keycloak.phone.authentication.forms.SupportPhonePages.FIELD_PHONE_NUMBER;
import static cc.coopersoft.keycloak.phone.providers.constants.PhoneConstants.FIELD_EMAIL;

public class RegistrationPhoneOrEmailUserCreation implements FormActionFactory, FormAction {

    public static final String PROVIDER_ID = "registration-phone-email-creation";
    public static final String MISSING_PHONE_NUMBER_OR_EMAIL = "requiredPhoneNumberOrEmail";

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

    static {
        CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
                .property()
                .name("registrationMethod")
                .type(ProviderConfigProperty.LIST_TYPE)
                .options("Email", "Phone")
                .label("Registration Method")
                .helpText("Choose whether to use email or phone number as the username.")
                .defaultValue("Phone")
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

    }

    @Override
    public void validate(ValidationContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        List<FormMessage> errors = new ArrayList<>();

        context.getEvent().detail(Details.REGISTER_METHOD, "form");
        String eventError = Errors.INVALID_REGISTRATION;
        KeycloakSession session = context.getSession();
        String phoneNumber = formData.getFirst(FIELD_PHONE_NUMBER);
        String credentialType = formData.getFirst(PhoneConstants.FIELD_CREDENTIAL_TYPE);

        boolean success = true;

        if (credentialType != null && credentialType.equals(PhoneConstants.CREDENTIAL_TYPE_PHONE)) {
            //使用手机号注册
            if (Validation.isBlank(phoneNumber)) {
                errors.add(new FormMessage(FIELD_PHONE_NUMBER, SupportPhonePages.Errors.MISSING.message()));
                context.error(Errors.INVALID_REGISTRATION);
                context.validationError(formData, errors);
                success = false;
            } else {
                try {
                    phoneNumber = Utils.canonicalizePhoneNumber(session, phoneNumber);
                    if (!Utils.isDuplicatePhoneAllowed(session) &&
                            Utils.findUserByPhone(session, context.getRealm(), phoneNumber).isPresent()) {
                        context.error(Errors.INVALID_REGISTRATION);
                        errors.add(new FormMessage(FIELD_PHONE_NUMBER, SupportPhonePages.Errors.EXISTS.message()));
                        context.validationError(formData, errors);
                        success = false;
                    }

                } catch (PhoneNumberInvalidException e) {
                    context.error(Errors.INVALID_REGISTRATION);
                    errors.add(new FormMessage(FIELD_PHONE_NUMBER, e.getErrorType().message()));
                    context.validationError(formData, errors);
                    success = false;
                }
            }

            String verificationCode = formData.getFirst(PhoneConstants.FIELD_VERIFICATION_CODE);
            TokenCodeRepresentation tokenCode = session.getProvider(PhoneVerificationCodeProvider.class).ongoingProcess(phoneNumber, TokenCodeType.REGISTRATION);

            if (Validation.isBlank(verificationCode) || tokenCode == null ||
                    !tokenCode.getCode().equals(verificationCode)) {
                context.error(Errors.INVALID_CODE);
                context.getEvent().detail(PhoneConstants.FIELD_PHONE_NUMBER, phoneNumber);
                errors.add(new FormMessage(PhoneConstants.FIELD_VERIFICATION_CODE, PhoneConstants.SMS_CODE_MISMATCH));
                context.validationError(formData, errors);
                success = false;
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
                if (pve.hasError(Messages.EMAIL_EXISTS)) {
                    context.error(Errors.EMAIL_IN_USE);
                } else if (pve.hasError(Messages.MISSING_EMAIL, Messages.MISSING_USERNAME, Messages.INVALID_EMAIL)) {
                    context.error(Errors.INVALID_REGISTRATION);
                } else if (pve.hasError(Messages.USERNAME_EXISTS)) {
                    context.error(Errors.USERNAME_IN_USE);
                }
                success = false;
                errors.addAll(Validation.getFormErrorsFromValidation(pve.getErrors()));
            }

        } else if (credentialType != null && credentialType.equals(PhoneConstants.CREDENTIAL_TYPE_EMAIL)) {
            //使用邮箱注册，验证电子邮箱
            formData.remove(PhoneConstants.FIELD_AREA_CODE);
            formData.remove(PhoneConstants.FIELD_PHONE_NUMBER);
            String email = formData.getFirst(Validation.FIELD_EMAIL);
            boolean emailValid = true;

            if (Validation.isBlank(email)) {
                errors.add(new FormMessage(RegistrationPage.FIELD_EMAIL, Messages.MISSING_EMAIL));
                emailValid = false;
            } else if (!Validation.isEmailValid(email)) {
                context.getEvent().detail(Details.EMAIL, email);
                errors.add(new FormMessage(RegistrationPage.FIELD_EMAIL, Messages.INVALID_EMAIL));
                emailValid = false;
            }

            System.out.println("emailValid: " + emailValid + ", duplicateEmailsAllowed: " + context.getRealm().isDuplicateEmailsAllowed() + ", email: " + email);

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
                    eventError = Errors.EMAIL_IN_USE;
                    formData.remove(Validation.FIELD_EMAIL);
                    context.getEvent().detail(Details.EMAIL, email);
                    errors.add(new FormMessage(RegistrationPage.FIELD_EMAIL, Messages.EMAIL_EXISTS));
                }
            }

            System.out.println("errors: " + errors.size() + ", success: " + success + ", emailValid: " + emailValid + ", eventError: " + eventError);

            //验证密码
            if (Validation.isBlank(formData.getFirst(RegistrationPage.FIELD_PASSWORD))) {
                errors.add(new FormMessage(RegistrationPage.FIELD_PASSWORD, Messages.MISSING_PASSWORD));
            } else if (!formData.getFirst(RegistrationPage.FIELD_PASSWORD).equals(formData.getFirst(RegistrationPage.FIELD_PASSWORD_CONFIRM))) {
                errors.add(new FormMessage(RegistrationPage.FIELD_PASSWORD_CONFIRM, Messages.INVALID_PASSWORD_CONFIRM));
            }

            System.out.println("errors: " + errors.size() + ", success: " + success + ", emailValid: " + emailValid + ", eventError: " + eventError);

            if (formData.getFirst(RegistrationPage.FIELD_PASSWORD) != null) {
                PolicyError err = context.getSession().getProvider(PasswordPolicyManagerProvider.class).validate(context.getRealm().isRegistrationEmailAsUsername() ? formData.getFirst(RegistrationPage.FIELD_EMAIL) : formData.getFirst(RegistrationPage.FIELD_USERNAME), formData.getFirst(RegistrationPage.FIELD_PASSWORD));
                if (err != null) {
                    errors.add(new FormMessage(RegistrationPage.FIELD_PASSWORD, err.getMessage(), err.getParameters()));
                }
            }

            System.out.println("验证密码完成");
            System.out.println("errors: " + errors.size() + ", success: " + success + ", emailValid: " + emailValid + ", eventError: " + eventError);

            context.getEvent().detail(Details.EMAIL, email);
            context.getEvent().detail(Details.USERNAME, email);
            formData.putSingle(UserModel.USERNAME, email);

            UserProfileProvider profileProvider = session.getProvider(UserProfileProvider.class);
            UserProfile profile = profileProvider.create(UserProfileContext.REGISTRATION_USER_CREATION, formData);

            String username = profile.getAttributes().getFirstValue(UserModel.USERNAME);
            context.getEvent().detail(Details.USERNAME, username);

            System.out.println("errors: " + errors.size() + ", success: " + success + ", emailValid: " + emailValid + ", eventError: " + eventError + ", username: " + username);

            for (FormMessage error : errors) {
                System.out.println("error: " + error.getMessage());
            }

            try {
                profile.validate();
                System.out.println("验证通过");
            } catch (ValidationException pve) {
                System.out.println("验证失败");
                if (pve.hasError(Messages.EMAIL_EXISTS)) {
                    context.error(Errors.EMAIL_IN_USE);
                } else if (pve.hasError(Messages.MISSING_EMAIL, Messages.MISSING_USERNAME, Messages.INVALID_EMAIL)) {
                    context.error(Errors.INVALID_REGISTRATION);
                } else if (pve.hasError(Messages.USERNAME_EXISTS)) {
                    context.error(Errors.USERNAME_IN_USE);
                }
                success = false;
                errors.addAll(Validation.getFormErrorsFromValidation(pve.getErrors()));
            }
        } else {
            //缺少参数
            eventError = Errors.INVALID_INPUT;
            errors.add(new FormMessage(null, MISSING_PHONE_NUMBER_OR_EMAIL));
        }

        if (!errors.isEmpty() || !success) {
            context.error(eventError);
            formData.remove(RegistrationPage.FIELD_PASSWORD);
            formData.remove(RegistrationPage.FIELD_PASSWORD_CONFIRM);
            context.validationError(formData, errors);
        } else {
            context.success();
        }
    }

    @Override
    public void success(FormContext context) {

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

        String phoneNumber = formData.getFirst(FIELD_PHONE_NUMBER);
        String email = formData.getFirst(UserModel.EMAIL);
        String username = formData.getFirst(UserModel.USERNAME);

        var session = context.getSession();

        String credentialType = formData.getFirst(PhoneConstants.FIELD_CREDENTIAL_TYPE);

        if (credentialType != null && credentialType.equals(PhoneConstants.CREDENTIAL_TYPE_PHONE)) {
            try {
                phoneNumber = Utils.canonicalizePhoneNumber(session, phoneNumber);
            } catch (PhoneNumberInvalidException e) {
                // verified in validate process
                throw new IllegalStateException();
            }
            username = phoneNumber;
            formData.add(UserModel.USERNAME, phoneNumber);
            context.getEvent().detail(Details.USERNAME, username)
                    .detail(Details.REGISTER_METHOD, "form")
                    .detail(FIELD_PHONE_NUMBER, phoneNumber);
        } else if (credentialType != null && credentialType.equals(PhoneConstants.CREDENTIAL_TYPE_EMAIL)) {
            System.out.println("使用邮箱注册");
            username = email;
            formData.add(UserModel.USERNAME, email);
            context.getEvent().detail(Details.EMAIL, email);
            context.getEvent().detail(Details.USERNAME, username).detail(Details.REGISTER_METHOD, "form").detail(FIELD_EMAIL, email);
        }

        UserProfileProvider profileProvider = session.getProvider(UserProfileProvider.class);
        UserProfile profile = profileProvider.create(UserProfileContext.REGISTRATION_USER_CREATION, formData);
        UserModel user = profile.create();

        //    UserModel user = context.getSession().users().addUser(context.getRealm(), username);
        user.setEnabled(true);
        context.setUser(user);

        context.getAuthenticationSession().setClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM, username);
        //AttributeFormDataProcessor.process(formData);

        context.getEvent().user(user);
        context.getEvent().success();
        context.newEvent().event(EventType.LOGIN);
        context.getEvent().client(context.getAuthenticationSession().getClient().getClientId())
                .detail(Details.REDIRECT_URI, context.getAuthenticationSession().getRedirectUri())
                .detail(Details.AUTH_METHOD, context.getAuthenticationSession().getProtocol());
        String authType = context.getAuthenticationSession().getAuthNote(Details.AUTH_TYPE);
        if (authType != null) {
            context.getEvent().detail(Details.AUTH_TYPE, authType);
        }
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

}
