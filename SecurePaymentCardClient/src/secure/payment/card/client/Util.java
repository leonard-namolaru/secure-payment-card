package secure.payment.card.client;

import java.util.HexFormat;
import java.security.Signature;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import com.oracle.javacard.ams.AMService;
import java.lang.reflect.InvocationTargetException;


/**
 * Fonctions utilitaires
 */
public final class Util {
	private Util() {}
	
	public static String bytesToHex(byte[] bytes) {
	    HexFormat hexFormat = HexFormat.of();
	    return hexFormat.formatHex(bytes);
	}
	
	public static byte[] hexToBytes(String hex) {
	    HexFormat hexFormat = HexFormat.of();
	    return hexFormat.parseHex(hex);
	}
	
	public static short bytesToShort(byte[] bytes) {
		String hex = bytesToHex(bytes);
		return Short.parseShort(hex, 16);
	}

	public static byte[] shortToBytes(short shortValue) {
	    byte[] bytes = new byte[Short.BYTES];
	    bytes[0] = (byte) (shortValue >> 8);
	    bytes[1] = (byte) shortValue;
		return bytes;
	}

	public static byte[] concatArrays(byte[] array1, byte[] array2) {
		byte[] newArray = new byte[array1.length + array2.length];
		
		// void java.lang.System.arraycopy(Object src, int srcPos, Object dest, int destPos, int length)
		System.arraycopy(array1, 0, newArray, 0, array1.length);
		System.arraycopy(array2, 0, newArray, array1.length, array2.length);
		return newArray;
	}
	
	public static Object createNewObjectInstanceByTypeName(String typeName) {
		Object object = null;
		
		try {
			object = Class.forName(typeName).getConstructor().newInstance();
		} catch (InstantiationException e) {
			object = null;
		} catch (IllegalAccessException e) {
			object = null;
		} catch (IllegalArgumentException e) {
			object = null;
		} catch (InvocationTargetException e) {
			object = null;
		} catch (NoSuchMethodException e) {
			object = null;
		} catch (SecurityException e) {
			object = null;
		} catch (ClassNotFoundException e) {
			object = null;
		} 
		
		return object;
	}
	
	public static byte[] createByteArrayWithSignature(byte[] data, Signature signatureObject) {
		byte[] signature = Crypto.signMessage(signatureObject, data);
		byte[] encodedSignatureForJavaCard = Crypto.getEncodedSignatureForJavaCard(signature);
		return concatArrays(data, encodedSignatureForJavaCard);
	}
	
	public static String convertByteArrayToString(byte[] array) {
		StringBuilder stringBuilder = new StringBuilder();
		for (byte b : array) {
			stringBuilder.append(String.format(" %02X ", b));
		}
		
		return stringBuilder.toString();
	}
	
	public static String convertApduCommandToString(CommandAPDU commandAPDU) {
		return String.format("CLA:%02X INS:%02X P1:%02X P2:%02X Nc:%02X Data:[%s]", 
				commandAPDU.getCLA(), commandAPDU.getINS(), commandAPDU.getP1(), commandAPDU.getP2(), 
				commandAPDU.getNc(), convertByteArrayToString(commandAPDU.getData()));
	}
	
	public static String convertApduCommandToLogString(CommandAPDU commandAPDU) {			
		return String.format("[%1$tF %1$tT %1$tL %1$tZ] [APDU-C] %2$s", 
				System.currentTimeMillis(), convertApduCommandToString(commandAPDU));
	}
	
	public static String convertApduResponseToLogString(ResponseAPDU responseAPDU) {
		return String.format("[%1$tF %1$tT %1$tL %1$tZ] [APDU-R] [%2$s] SW:%3$04X", 
				System.currentTimeMillis(), convertByteArrayToString(responseAPDU.getData()), responseAPDU.getSW());
	}
	
	public static String getArg(String[] args, String argName, String defaultValue) {
		String value = defaultValue;

		for (String param : args) {
			if (param.startsWith("-" + argName + "=")) {
				value = param.substring(param.indexOf('=') + 1);
			}
		}

		if(value == null || value.length() == 0) {
			value = defaultValue;
		}
		return value;
	}
	
	
	public static void debugApplicationManagementService(AMService applicationManagementService) {
		for (String key : applicationManagementService.getPropertiesKeys()) {
			System.out.println(key + " = " + applicationManagementService.getProperty(key));
		}
	}
	
	public static String convertResponseStatusCodeToString(ResponseAPDU response, boolean tryReadData) {
		StringBuilder message = new StringBuilder();
		int responseStatusCode = response.getSW(); 
		
		if (responseStatusCode == CardCommunicationChannel.STATUS_OK) {
			
			message.append("Opération réussie");
			
		} else if (responseStatusCode == SecurePaymentCardConstants.SW_COMMUNICATION_PROBLEM) {
			
			message.append("Une erreur s'est produite lors de la communication avec la carte à puce.");
			
		} else if ((SecurePaymentCardConstants.SW_PIN_EXCEPTION_PREFIX & responseStatusCode) 
				== SecurePaymentCardConstants.SW_PIN_EXCEPTION_PREFIX) {
			
			message.append(convertCardPinExceptionToString(responseStatusCode));
			
		} else if ((SecurePaymentCardConstants.SW_CRYPTO_EXCEPTION_PREFIX & responseStatusCode)
				== SecurePaymentCardConstants.SW_CRYPTO_EXCEPTION_PREFIX) {
			
			message.append(convertCardCryptoExceptionToString(responseStatusCode));
			
		} else if ((SecurePaymentCardConstants.SW_TRANSACTION_EXCEPTION_PREFIX & (short) responseStatusCode)
				== SecurePaymentCardConstants.SW_TRANSACTION_EXCEPTION_PREFIX) {
			message.append(convertCardTransactionExceptionToString(responseStatusCode));
			
		} else {
			message.append("Réponse inattendue");
		}
		
		if (tryReadData) {
			byte[] data = response.getData();
			
			if (data.length > 0) {
				message.append("\n");
			}
			
			for (byte b : data) {
				message.append(String.format("%02X ", b));
			}
		}
		
		return message.toString();
	}
	
	private static String convertCardPinExceptionToString(int responseStatusCode) {
		switch ((short) responseStatusCode) {
		case SecurePaymentCardConstants.SW_PIN_EXCEPTION_PREFIX | SecurePaymentCardConstants.SW_PIN_VERIFICATION_FAILED:
			return "Échec de la vérification du code PIN";
		case SecurePaymentCardConstants.SW_PIN_EXCEPTION_PREFIX | SecurePaymentCardConstants.SW_PIN_VERIFICATION_REQUIRED: 
			return "Une vérification par code PIN est requise.";
		default:
			return "PinException : Réponse inattendue";
		}
	}
	
	private static String convertCardCryptoExceptionToString(int responseStatusCode) {
		switch ((short) responseStatusCode) {
		case SecurePaymentCardConstants.SW_CRYPTO_EXCEPTION_PREFIX | SecurePaymentCardConstants.SW_KEY_GENERATION_FAILED:
			return "La génération de clés a échoué";
		case SecurePaymentCardConstants.SW_CRYPTO_EXCEPTION_PREFIX | SecurePaymentCardConstants.SW_PIN_VERIFICATION_REQUIRED: 
			return "Une vérification par code PIN est requise.";
		default:
			return "CryptoException : Réponse inattendue";
		}
	}

	private static String convertCardTransactionExceptionToString(int responseStatusCode) {
		switch ((short) responseStatusCode) {
		case SecurePaymentCardConstants.SW_TRANSACTION_EXCEPTION_PREFIX | SecurePaymentCardConstants.SW_INVALID_TRANSACTION:
			return "Montant de transaction invalide";
		case SecurePaymentCardConstants.SW_TRANSACTION_EXCEPTION_PREFIX | SecurePaymentCardConstants.SW_NEGATIVE_BALANCE: 
			return "Solde insuffisant.";
		case SecurePaymentCardConstants.SW_TRANSACTION_EXCEPTION_PREFIX | SecurePaymentCardConstants.SW_MAXIMUM_BALANCE: 
			return "Le solde dépasse le maximum";
		default:
			return "TransactionException : Réponse inattendue";
		}
	}
}