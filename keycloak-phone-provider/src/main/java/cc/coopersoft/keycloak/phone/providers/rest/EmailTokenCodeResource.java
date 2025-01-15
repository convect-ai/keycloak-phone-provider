package cc.coopersoft.keycloak.phone.providers.rest;

import cc.coopersoft.keycloak.phone.Utils;
import cc.coopersoft.keycloak.phone.providers.constants.TokenCodeType;
import cc.coopersoft.keycloak.phone.providers.exception.MessageSendException;
import cc.coopersoft.keycloak.phone.providers.representations.SendCodeResult;
import cc.coopersoft.keycloak.phone.providers.representations.TokenCodeRepresentation;
import cc.coopersoft.keycloak.phone.providers.spi.EmailVerificationCodeProvider;
import org.jboss.logging.Logger;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.validation.Validation;

import javax.validation.constraints.NotBlank;
import javax.ws.rs.*;
import javax.ws.rs.core.Response;
import java.time.Instant;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON_TYPE;

public class EmailTokenCodeResource {

    private static final Logger logger = Logger.getLogger(TokenCodeResource.class);
    protected final KeycloakSession session;
    protected final TokenCodeType tokenCodeType;

    EmailTokenCodeResource(KeycloakSession session, TokenCodeType tokenCodeType) {
        this.session = session;
        this.tokenCodeType = tokenCodeType;
    }


    @GET
    @NoCache
    @Path("")
    @Produces(APPLICATION_JSON)
    public Response getTokenCode(@NotBlank @QueryParam("email") String email, @QueryParam("kind") String kind) {

        if (Validation.isBlank(email)) throw new BadRequestException("Must supply a email address");

        // validate email
        if (!Utils.isValidEmail(email)) {
            throw new BadRequestException("Email address is invalid");
        }

        // check if the email is already registered
        if (!session.getContext().getRealm().isDuplicateEmailsAllowed() &&
            TokenCodeType.REGISTRATION.equals(tokenCodeType) &&
            session.users().getUserByEmail(session.getContext().getRealm(), email) != null) {
            throw new ForbiddenException("Email address already exists");
        }

        // everybody phones authenticator send AUTH code
        if (!TokenCodeType.REGISTRATION.equals(tokenCodeType) &&
            !TokenCodeType.AUTH.equals(tokenCodeType) &&
            !TokenCodeType.VERIFY.equals(tokenCodeType) &&
            !TokenCodeType.RESET.equals(tokenCodeType)) {
            throw new ForbiddenException("Email Token Code Type only supports REGISTRATION and RESET");
        }

        logger.info(String.format("Requested %s code to %s", tokenCodeType.label, email));

        SendCodeResult result = sendTokenCode(email, session.getContext().getConnection().getRemoteAddr(), tokenCodeType, kind);

        String response = String.format("{\"expires_in\":%s, \"allow_resend_in\":%s, \"sent\":%s}", result.getExpiresIn(), result.getNextResendIn(), result.isSent());

        return Response.ok(response, APPLICATION_JSON_TYPE).build();
    }

    private EmailVerificationCodeProvider getTokenCodeService() {
        return session.getProvider(EmailVerificationCodeProvider.class);
    }

    public SendCodeResult sendTokenCode(String email, String sourceAddr, TokenCodeType type, String kind) {

        logger.info("send code to: " + email);

        if (getTokenCodeService().isAbusing(email, type, sourceAddr, 3, 10)) {
            throw new ForbiddenException("You requested the maximum number of messages the last hour");
        }

        TokenCodeRepresentation ongoing = getTokenCodeService().ongoingProcess(email, type);

        if (ongoing != null) {
            long timeSinceLastSent = Instant.now().toEpochMilli() - ongoing.getCreatedAt().getTime();
            if (timeSinceLastSent < 60 * 1000) {
                logger.info(String.format("No need of sending a new %s code for %s", type.label, email));
                int expiresAt = (int) (ongoing.getExpiresAt().getTime() - Instant.now().toEpochMilli()) / 1000;
                int nextResendIn = (int) (ongoing.getCreatedAt().getTime() + 60 * 1000 - Instant.now().toEpochMilli());
                return new SendCodeResult(expiresAt, nextResendIn, false);
            } else {
                // Create an ongoing process, which holds the same code as the previous one
                int expiresIn = (int) (ongoing.getExpiresAt().getTime() - Instant.now().toEpochMilli()) / 1000;
                // Make sure that expiresIn is at least tokenResendIn
                if (expiresIn < 60) {
                    expiresIn = 60;
                }
                try {
                    getTokenCodeService().sendEmailMessage(type, email, ongoing.getCode(), 600, kind);
                    // make the old process expired
                    getTokenCodeService().deprecateCode(ongoing);
                    TokenCodeRepresentation ongoingNew = ongoing.clone();
                    getTokenCodeService().persistCode(ongoingNew, type, expiresIn);

                } catch (MessageSendException e) {
                    logger.error(String.format("Message sending to %s failed with %s: %s",
                            email, e.getErrorCode(), e.getErrorMessage()));
                    throw new ServiceUnavailableException("Internal server error");
                }

                return new SendCodeResult(expiresIn, 60, true);
            }
        }

        TokenCodeRepresentation token = TokenCodeRepresentation.forPhoneNumber(email);

        try {
            getTokenCodeService().sendEmailMessage(type, email, token.getCode(), 600, kind);
            getTokenCodeService().persistCode(token, type, 600);

            logger.info(String.format("Sent %s code to %s", type.label, email));

        } catch (MessageSendException e) {

            logger.error(String.format("Message sending to %s failed with %s: %s", email, e.getErrorCode(), e.getErrorMessage()));
            throw new ServiceUnavailableException("Internal server error");
        }

        return new SendCodeResult(600, 60, true);
    }

}
