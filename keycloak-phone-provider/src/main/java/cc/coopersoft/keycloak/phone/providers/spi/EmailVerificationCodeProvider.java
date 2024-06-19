package cc.coopersoft.keycloak.phone.providers.spi;

import cc.coopersoft.keycloak.phone.providers.constants.TokenCodeType;
import cc.coopersoft.keycloak.phone.providers.exception.MessageSendException;
import cc.coopersoft.keycloak.phone.providers.representations.TokenCodeRepresentation;
import org.keycloak.models.UserModel;
import org.keycloak.provider.Provider;

public interface EmailVerificationCodeProvider extends Provider {

    TokenCodeRepresentation ongoingProcess(String email, TokenCodeType tokenCodeType);

    boolean isAbusing(String email, TokenCodeType tokenCodeType,String sourceAddr ,int sourceHourMaximum,int targetHourMaximum);

    void persistCode(TokenCodeRepresentation tokenCode, TokenCodeType tokenCodeType, int tokenExpiresIn);

    void validateCode(UserModel user, String email, String code);

    void validateCode(UserModel user, String email, String code, TokenCodeType tokenCodeType);

    void validateProcess(String tokenCodeId, UserModel user);

    void tokenValidated(UserModel user, String email, String tokenCodeId);

    void sendEmailMessage(TokenCodeType type, String phoneNumber, String code , int expires , String kind) throws MessageSendException;

}
