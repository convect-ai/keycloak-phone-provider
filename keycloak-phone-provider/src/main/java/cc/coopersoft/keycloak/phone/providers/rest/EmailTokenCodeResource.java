package cc.coopersoft.keycloak.phone.providers.rest;

import cc.coopersoft.keycloak.phone.Utils;
import cc.coopersoft.keycloak.phone.providers.constants.TokenCodeType;
import cc.coopersoft.keycloak.phone.providers.exception.MessageSendException;
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

        // everybody phones authenticator send AUTH code
        if (!TokenCodeType.REGISTRATION.equals(tokenCodeType) && !TokenCodeType.AUTH.equals(tokenCodeType) && !TokenCodeType.VERIFY.equals(tokenCodeType)) {
            throw new ForbiddenException("Email Token Code Type only supports REGISTRATION");
        }

        logger.info(String.format("Requested %s code to %s", tokenCodeType.label, email));

        int tokenExpiresIn = sendTokenCode(email, session.getContext().getConnection().getRemoteAddr(), tokenCodeType, kind);

        String response = String.format("{\"expires_in\":%s}", tokenExpiresIn);

        return Response.ok(response, APPLICATION_JSON_TYPE).build();
    }

    private EmailVerificationCodeProvider getTokenCodeService() {
        return session.getProvider(EmailVerificationCodeProvider.class);
    }

    public int sendTokenCode(String email, String sourceAddr, TokenCodeType type, String kind) {

        logger.info("send code to: " + email);

        if (getTokenCodeService().isAbusing(email, type, sourceAddr, 3, 10)) {
            throw new ForbiddenException("You requested the maximum number of messages the last hour");
        }

        TokenCodeRepresentation ongoing = getTokenCodeService().ongoingProcess(email, type);
        if (ongoing != null) {
            logger.info(String.format("No need of sending a new %s code for %s", type.label, email));
            return (int) (ongoing.getExpiresAt().getTime() - Instant.now().toEpochMilli()) / 1000;
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

        return 600;
    }

}
