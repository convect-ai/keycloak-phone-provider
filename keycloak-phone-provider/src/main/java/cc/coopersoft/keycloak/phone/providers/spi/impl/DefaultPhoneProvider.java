package cc.coopersoft.keycloak.phone.providers.spi.impl;

import cc.coopersoft.common.OptionalUtils;
import cc.coopersoft.keycloak.phone.providers.representations.SendCodeResult;
import cc.coopersoft.keycloak.phone.providers.spi.PhoneProvider;
import cc.coopersoft.keycloak.phone.providers.spi.PhoneVerificationCodeProvider;
import cc.coopersoft.keycloak.phone.providers.constants.TokenCodeType;
import cc.coopersoft.keycloak.phone.providers.exception.MessageSendException;
import cc.coopersoft.keycloak.phone.providers.representations.TokenCodeRepresentation;
import cc.coopersoft.keycloak.phone.providers.spi.MessageSenderService;
import org.jboss.logging.Logger;
import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.validation.Validation;
import org.slf4j.LoggerFactory;

import javax.ws.rs.ForbiddenException;
import javax.ws.rs.ServiceUnavailableException;
import java.time.Instant;
import java.util.Optional;

public class DefaultPhoneProvider implements PhoneProvider {

    private static final Logger logger = Logger.getLogger(DefaultPhoneProvider.class);
    private static final org.slf4j.Logger log = LoggerFactory.getLogger(DefaultPhoneProvider.class);
    private final KeycloakSession session;
    private final String service;
    private final int tokenExpiresIn;
    private final int tokenResendIn;
    private final int targetHourMaximum;
    private final int sourceHourMaximum;

    private final Scope config;

    DefaultPhoneProvider(KeycloakSession session, Scope config) {
        this.session = session;
        this.config = config;


        this.service = session.listProviderIds(MessageSenderService.class)
                .stream().filter(s -> s.equals(config.get("service")))
                .findFirst().orElse(
                        session.listProviderIds(MessageSenderService.class)
                                .stream().findFirst().orElse(null)
                );

        if (Validation.isBlank(this.service)) {
            logger.error("Message sender service provider not found!");
        }

        if (Validation.isBlank(config.get("service")))
            logger.warn("No message sender service provider specified! Default provider'" +
                    this.service + "' will be used. You can use keycloak start param '--spi-phone-default-service' to specify a different one. ");

        this.tokenExpiresIn = config.getInt("tokenExpiresIn", 600);
        this.tokenResendIn = config.getInt("tokenResendIn", 60);
        this.targetHourMaximum = config.getInt("targetHourMaximum", 3);
        this.sourceHourMaximum = config.getInt("sourceHourMaximum", 10);
    }

    @Override
    public void close() {
    }


    private PhoneVerificationCodeProvider getTokenCodeService() {
        return session.getProvider(PhoneVerificationCodeProvider.class);
    }

    private String getRealmName() {
        return session.getContext().getRealm().getName();
    }

    private Optional<String> getStringConfigValue(String configName) {
        return OptionalUtils.ofBlank(OptionalUtils.ofBlank(config.get(getRealmName() + "-" + configName))
                .orElse(config.get(configName)));
    }

    private boolean getBooleanConfigValue(String configName, boolean defaultValue) {
        Boolean result = config.getBoolean(getRealmName() + "-" + configName, null);
        if (result == null) {
            result = config.getBoolean(configName, defaultValue);
        }
        return result;
    }

    @Override
    public boolean isDuplicatePhoneAllowed() {
        return getBooleanConfigValue("duplicate-phone", false);
    }

    @Override
    public boolean validPhoneNumber() {
        return getBooleanConfigValue("valid-phone", true);
    }

    @Override
    public boolean compatibleMode() {
        return getBooleanConfigValue("compatible", false);
    }

    @Override
    public int otpExpires() {
        return getStringConfigValue("otp-expires").map(Integer::valueOf).orElse(60 * 60);
    }

    @Override
    public Optional<String> canonicalizePhoneNumber() {
        return getStringConfigValue("canonicalize-phone-numbers");
    }

    @Override
    public Optional<String> defaultPhoneRegion() {
        return getStringConfigValue("phone-default-region");
    }

    @Override
    public Optional<String> phoneNumberRegex() {
        return getStringConfigValue("number-regex");
    }

    @Override
    public SendCodeResult sendTokenCode(String phoneNumber, String sourceAddr, TokenCodeType type, String kind) {

        logger.info("send code to:" + phoneNumber);

        if (getTokenCodeService().isAbusing(phoneNumber, type, sourceAddr, sourceHourMaximum, targetHourMaximum)) {
            throw new ForbiddenException("You requested the maximum number of messages the last hour");
        }

        TokenCodeRepresentation ongoing = getTokenCodeService().ongoingProcess(phoneNumber, type);
        if (ongoing != null) {
            long timeSinceLastSent = Instant.now().toEpochMilli() - ongoing.getCreatedAt().getTime();
            if (timeSinceLastSent < tokenResendIn * 1000L) {
                logger.info(String.format("No need of sending a new %s code for %s", type.label, phoneNumber));
                int expiresAt = (int) (ongoing.getExpiresAt().getTime() - Instant.now().toEpochMilli()) / 1000;
                int nextResendIn = (int) (ongoing.getCreatedAt().getTime() + tokenResendIn * 1000 - Instant.now().toEpochMilli());
                return new SendCodeResult(expiresAt, nextResendIn, false);
            } else {
                // Create an ongoing process, which holds the same code as the previous one
                int expiresIn = (int) (ongoing.getExpiresAt().getTime() - Instant.now().toEpochMilli()) / 1000;
                // Make sure that expiresIn is at least tokenResendIn
                if (expiresIn < tokenResendIn) {
                    expiresIn = tokenResendIn;
                }
                try {
                    session.getProvider(MessageSenderService.class, service).sendSmsMessage(type, phoneNumber, ongoing.getCode(),tokenExpiresIn, kind);
                    // make the old process expired
                    getTokenCodeService().deprecateCode(ongoing);
                    TokenCodeRepresentation ongoingNew = ongoing.clone();
                    getTokenCodeService().persistCode(ongoingNew, type, expiresIn);

                } catch (MessageSendException e) {
                    logger.error(String.format("Message sending to %s failed with %s: %s",
                            phoneNumber, e.getErrorCode(), e.getErrorMessage()));

                    if (e.getErrorCode().equals("isv.BUSINESS_LIMIT_CONTROL")) {
                        throw new ForbiddenException("You requested the maximum number of messages the last hour");
                    }

                    throw new ServiceUnavailableException("Internal server error");
                } catch (Exception e) {
                    logger.error(String.format("Message sending to %s failed with %s: %s",
                            phoneNumber, e.getClass().getName(), e.getMessage()));
                    logger.error(String.format("我靠，啥问题啊, %s", e.getClass().getName()));
                    logger.error(String.format("我靠，啥问题啊, %s", e.getMessage()));
                    throw new ServiceUnavailableException("Internal server error");
                }

                return new SendCodeResult(expiresIn, tokenResendIn, true);
            }
        }

        TokenCodeRepresentation token = TokenCodeRepresentation.forPhoneNumber(phoneNumber);

        try {
            session.getProvider(MessageSenderService.class, service).sendSmsMessage(type, phoneNumber, token.getCode(), tokenExpiresIn, kind);
            getTokenCodeService().persistCode(token, type, tokenExpiresIn);

            logger.info(String.format("Sent %s code to %s over %s", type.label, phoneNumber, service));

        } catch (MessageSendException e) {

            logger.error(String.format("Message sending to %s failed with %s: %s",
                    phoneNumber, e.getErrorCode(), e.getErrorMessage()));
            throw new ServiceUnavailableException("Internal server error");
        }

        return new SendCodeResult(tokenExpiresIn, tokenResendIn, true);
    }

}
