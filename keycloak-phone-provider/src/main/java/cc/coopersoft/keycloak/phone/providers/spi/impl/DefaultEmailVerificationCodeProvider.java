package cc.coopersoft.keycloak.phone.providers.spi.impl;

import cc.coopersoft.keycloak.phone.providers.constants.TokenCodeType;
import cc.coopersoft.keycloak.phone.providers.exception.MessageSendException;
import cc.coopersoft.keycloak.phone.providers.jpa.TokenCode;
import cc.coopersoft.keycloak.phone.providers.representations.TokenCodeRepresentation;
import cc.coopersoft.keycloak.phone.providers.spi.EmailVerificationCodeProvider;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.models.*;

import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.TemporalType;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.ForbiddenException;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

public class DefaultEmailVerificationCodeProvider implements EmailVerificationCodeProvider {


    private static final Logger logger = Logger.getLogger(DefaultPhoneVerificationCodeProvider.class);
    private final KeycloakSession session;

    public DefaultEmailVerificationCodeProvider(KeycloakSession session) {
        this.session = session;
        if (getRealm() == null) {
            throw new IllegalStateException("The service cannot accept a session without a realm in its context.");
        }
    }

    private EntityManager getEntityManager() {
        return session.getProvider(JpaConnectionProvider.class).getEntityManager();
    }

    private RealmModel getRealm() {
        return session.getContext().getRealm();
    }

    @Override
    public TokenCodeRepresentation ongoingProcess(String email, TokenCodeType tokenCodeType) {

        try {
            TokenCode entity = getEntityManager()
                    .createNamedQuery("ongoingProcess", TokenCode.class)
                    .setParameter("realmId", getRealm().getId())
                    .setParameter("phoneNumber", email)
                    .setParameter("now", new Date(), TemporalType.TIMESTAMP)
                    .setParameter("type", tokenCodeType.name())
                    .getSingleResult();

            TokenCodeRepresentation tokenCodeRepresentation = new TokenCodeRepresentation();

            tokenCodeRepresentation.setId(entity.getId());
            tokenCodeRepresentation.setPhoneNumber(entity.getPhoneNumber());
            tokenCodeRepresentation.setCode(entity.getCode());
            tokenCodeRepresentation.setType(entity.getType());
            tokenCodeRepresentation.setCreatedAt(entity.getCreatedAt());
            tokenCodeRepresentation.setExpiresAt(entity.getExpiresAt());
            tokenCodeRepresentation.setConfirmed(entity.getConfirmed());

            return tokenCodeRepresentation;
        } catch (NoResultException e) {
            return null;
        }
    }

    @Override
    public boolean isAbusing(String email, TokenCodeType tokenCodeType,
                             String sourceAddr, int sourceHourMaximum, int targetHourMaximum) {

        Date oneHourAgo = new Date(System.currentTimeMillis() - TimeUnit.HOURS.toMillis(1));

        if (targetHourMaximum > 0) {
            long targetCount = (getEntityManager()
                    .createNamedQuery("processesSinceTarget", Long.class)
                    .setParameter("realmId", getRealm().getId())
                    .setParameter("phoneNumber", email)
                    .setParameter("date", oneHourAgo, TemporalType.TIMESTAMP)
                    .setParameter("type", tokenCodeType.name())
                    .getSingleResult());
            return targetCount > targetHourMaximum;
        }

        if (sourceHourMaximum > 0) {
            long sourceCount = (getEntityManager()
                    .createNamedQuery("processesSinceSource", Long.class)
                    .setParameter("realmId", getRealm().getId())
                    .setParameter("addr", sourceAddr)
                    .setParameter("date", oneHourAgo, TemporalType.TIMESTAMP)
                    .setParameter("type", tokenCodeType.name())
                    .getSingleResult());
            return sourceCount > sourceHourMaximum;
        }

        return false;
    }

    @Override
    public void persistCode(TokenCodeRepresentation tokenCode, TokenCodeType tokenCodeType, int tokenExpiresIn) {

        TokenCode entity = new TokenCode();
        Instant now = Instant.now();

        entity.setId(tokenCode.getId());
        entity.setRealmId(getRealm().getId());
        entity.setPhoneNumber(tokenCode.getPhoneNumber());
        entity.setCode(tokenCode.getCode());
        entity.setType(tokenCodeType.name());
        entity.setCreatedAt(Date.from(now));
        entity.setExpiresAt(Date.from(now.plusSeconds(tokenExpiresIn)));
        entity.setConfirmed(tokenCode.getConfirmed());
        if (session.getContext().getConnection() != null) {
            entity.setIp(session.getContext().getConnection().getRemoteAddr());
            entity.setPort(session.getContext().getConnection().getRemotePort());
            entity.setHost(session.getContext().getConnection().getRemoteHost());
        }

        getEntityManager().persist(entity);
    }

    @Override
    public void validateCode(UserModel user, String email, String code) {
        validateCode(user, email, code, TokenCodeType.VERIFY);
    }

    @Override
    public void validateCode(UserModel user, String email, String code, TokenCodeType tokenCodeType) {

        logger.info(String.format("valid %s , email: %s, code: %s", tokenCodeType, email, code));

        TokenCodeRepresentation tokenCode = ongoingProcess(email, tokenCodeType);
        if (tokenCode == null)
            throw new BadRequestException(String.format("There is no valid ongoing %s process", tokenCodeType.label));

        if (!tokenCode.getCode().equals(code)) throw new ForbiddenException("Code does not match with expected value");

        logger.info(String.format("User %s correctly answered the %s code", user.getId(), tokenCodeType.label));

        tokenValidated(user, email, tokenCode.getId());
    }

    @Override
    public void tokenValidated(UserModel user, String email, String tokenCodeId) {

        session.users()
                .searchForUserByUserAttributeStream(session.getContext().getRealm(), "email", email)
                .filter(u -> !u.getId().equals(user.getId()))
                .forEach(u -> {
                    logger.info(String.format("User %s also has email %s. Un-verifying.", u.getId(), email));

                    u.setEmailVerified(false);
                    u.addRequiredAction(UserModel.RequiredAction.UPDATE_EMAIL);
                });

        user.setEmailVerified(true);
        user.setSingleAttribute("email", email);

        user.removeRequiredAction(UserModel.RequiredAction.UPDATE_EMAIL);

        validateProcess(tokenCodeId, user);
    }

    @Override
    public void validateProcess(String tokenCodeId, UserModel user) {
        TokenCode entity = getEntityManager().find(TokenCode.class, tokenCodeId);
        entity.setConfirmed(true);
        entity.setByWhom(user.getId());
        getEntityManager().persist(entity);
    }

    @Override
    public void sendEmailMessage(TokenCodeType type, String email, String code, int expires, String kind) throws MessageSendException {

        UserModel user = new VirtualUserModel();
        user.setEmail(email);

        RealmModel realm = session.getContext().getRealm();

        Map<String, Object> attributes = new HashMap<>();
        attributes.put("code", code);

        try {
            session
                    .getProvider(EmailTemplateProvider.class)
                    .setRealm(realm)
                    .setUser(user)
                    .send("emailVerificationSubject", "email-verification-with-code.ftl", attributes);
        } catch (EmailException e) {
            logger.error("Failed to send verification email", e);
            throw new MessageSendException("Failed to send verification email", e);
        }
    }

    @Override
    public void close() {
    }


    public static class VirtualUserModel implements UserModel {

        private String email = "";

        @Override
        public Stream<RoleModel> getRealmRoleMappingsStream() {
            return Stream.empty();
        }

        @Override
        public Stream<RoleModel> getClientRoleMappingsStream(ClientModel clientModel) {
            return Stream.empty();
        }

        @Override
        public boolean hasRole(RoleModel roleModel) {
            return false;
        }

        @Override
        public void grantRole(RoleModel roleModel) {

        }

        @Override
        public Stream<RoleModel> getRoleMappingsStream() {
            return Stream.empty();
        }

        @Override
        public void deleteRoleMapping(RoleModel roleModel) {

        }

        @Override
        public String getId() {
            return "";
        }

        @Override
        public String getUsername() {
            return "";
        }

        @Override
        public void setUsername(String s) {

        }

        @Override
        public Long getCreatedTimestamp() {
            return System.currentTimeMillis();
        }

        @Override
        public void setCreatedTimestamp(Long aLong) {

        }

        @Override
        public boolean isEnabled() {
            return false;
        }

        @Override
        public void setEnabled(boolean b) {

        }

        @Override
        public void setSingleAttribute(String s, String s1) {

        }

        @Override
        public void setAttribute(String s, List<String> list) {

        }

        @Override
        public void removeAttribute(String s) {

        }

        @Override
        public String getFirstAttribute(String s) {
            return "";
        }

        @Override
        public Stream<String> getAttributeStream(String s) {
            return Stream.empty();
        }

        @Override
        public Map<String, List<String>> getAttributes() {
            return Map.of();
        }

        @Override
        public Stream<String> getRequiredActionsStream() {
            return Stream.empty();
        }

        @Override
        public void addRequiredAction(String s) {

        }

        @Override
        public void removeRequiredAction(String s) {

        }

        @Override
        public String getFirstName() {
            return "";
        }

        @Override
        public void setFirstName(String s) {

        }

        @Override
        public String getLastName() {
            return "";
        }

        @Override
        public void setLastName(String s) {

        }

        @Override
        public String getEmail() {
            return email; // 需要发送邮件的地址
        }

        @Override
        public void setEmail(String s) {
            email = s;
        }

        @Override
        public boolean isEmailVerified() {
            return false;
        }

        @Override
        public void setEmailVerified(boolean b) {

        }

        @Override
        public Stream<GroupModel> getGroupsStream() {
            return Stream.empty();
        }

        @Override
        public void joinGroup(GroupModel groupModel) {

        }

        @Override
        public void leaveGroup(GroupModel groupModel) {

        }

        @Override
        public boolean isMemberOf(GroupModel groupModel) {
            return false;
        }

        @Override
        public String getFederationLink() {
            return "";
        }

        @Override
        public void setFederationLink(String s) {

        }

        @Override
        public String getServiceAccountClientLink() {
            return "";
        }

        @Override
        public void setServiceAccountClientLink(String s) {

        }

        @Override
        public SubjectCredentialManager credentialManager() {
            return null;
        }
    }

}
