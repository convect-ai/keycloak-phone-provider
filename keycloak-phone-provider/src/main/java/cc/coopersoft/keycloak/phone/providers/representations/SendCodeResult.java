package cc.coopersoft.keycloak.phone.providers.representations;

import lombok.Data;

@Data
public class SendCodeResult {

    private int expiresIn;
    private int nextResendIn;
    private boolean sent;

    public SendCodeResult(int expiresIn, int nextResendIn, boolean sent) {
        this.expiresIn = expiresIn;
        this.nextResendIn = nextResendIn;
        this.sent = sent;
    }

}
