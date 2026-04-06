package secure.payment.card.server.exception;

public enum ErrorCodeEnum {
    BAD_CREDENTIALS (1),
    CARD_NOT_FOUND (2),
    ACCESS_DENIED (3),
    JWT_INVALID(4),
    JWT_EXPIRED (5),
    ;

    private final int codeId;
    ErrorCodeEnum(int codeId) {
        this.codeId = codeId;
    }
    public String getCodeId() {
        return String.format("%02d", codeId);
    }
}