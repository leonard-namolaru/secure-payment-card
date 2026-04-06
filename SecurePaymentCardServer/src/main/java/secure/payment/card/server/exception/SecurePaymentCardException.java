package secure.payment.card.server.exception;

import lombok.Getter;

@Getter
public class SecurePaymentCardException extends RuntimeException {
    private final ErrorCodeEnum code;
    private final String description;

    public SecurePaymentCardException(ErrorCodeEnum code, String message, String description) {
        super(message);
        this.code = code;
        this.description = description;
    }

    public SecurePaymentCardException(ErrorCodeEnum code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
        this.description = message;
    }

    public String getCode() {
        return code.getCodeId();
    }
}
