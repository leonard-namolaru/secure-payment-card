package secure.payment.card.client;

public class SecurePaymentCardConstants {
    final static byte CLA_SECURE_PAYMENT_CARD                  = (byte) 0x80;
    
    final static byte INS_DEBIT                                = (byte) 0x10;
    final static byte INS_CREDIT                               = (byte) 0x20;
    final static byte INS_VERIFY_PIN                           = (byte) 0x30;
    final static byte INS_GET_BALANCE                          = (byte) 0x40;
    final static byte INS_GET_PUBLIC_KEY                       = (byte) 0x50;
    final static byte INS_PUT_PUBLIC_KEY                       = (byte) 0x60;
    final static byte INS_GET_PAYEMENT_CARD_ID                 = (byte) 0x70;
    
    final static short SW_COMMUNICATION_PROBLEM                = (short) 0x0000;
    final static short SW_PIN_EXCEPTION_PREFIX                 = (short) 0xf100;
    final static short SW_CRYPTO_EXCEPTION_PREFIX              = (short) 0xf200;
    final static short SW_TRANSACTION_EXCEPTION_PREFIX         = (short) 0xf300;

    // javacard.framework.PINException 
    // public static final short	ILLEGAL_VALUE	              1
    // public static final short	ILLEGAL_STATE	              2
    final static short SW_PIN_TOO_SMALL                        =  3;
    final static short SW_PIN_VERIFICATION_FAILED              =  4;
    final static short SW_PIN_VERIFICATION_REQUIRED            =  5;
    
    // javacard.security.CryptoException 
    // public static final short	ILLEGAL_VALUE	              1
    // public static final short	UNINITIALIZED_KEY	          2
    // public static final short	NO_SUCH_ALGORITHM	          3
    // public static final short	INVALID_INIT		          4
    // public static final short	ILLEGAL_USE			          5
    final static short SW_KEY_GENERATION_FAILED                =  6;
    final static short SW_SIGNATURE_INITIALIZATION_FAILED      =  7;
    final static short SW_WRONG_SIGNATURE                      =  8;

    // javacard.framework.TransactionException
    // public static final short 	IN_PROGRESS 	              1
    // public static final short 	NOT_IN_PROGRESS 	          2
    // public static final short 	BUFFER_FULL 	              3
    // public static final short 	INTERNAL_FAILURE 	          4
    // public static final short 	ILLEGAL_USE 	              5
    final static short SW_INVALID_TRANSACTION                  =  6;
    final static short SW_MAXIMUM_BALANCE                      =  7;
    final static short SW_NEGATIVE_BALANCE                     =  8;
    
    final static byte PIN_SIZE                                 =  6;
    final static short MAX_BALANCE                             =  0x7FFF;
    final static byte SIGNATURE_SIZE                           =  64;
    final static byte MAX_TRANSACTION                          =  127;
    final static short MONOTONIC_COUNTER_SIZE                  =  4;
    final static byte PIN_MAX_INCORRECT_TRIES                  =  3;
    final static byte PARAMETER_DATA_MAXIMUM_SIZE              =  127;
    
    final static byte EXIT_SUCCESS                             =  0;
    final static byte EXIT_FAILURE                             =  1;
}