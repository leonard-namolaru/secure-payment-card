package secure.payment.card.client;

import java.math.BigInteger;
import javax.smartcardio.ResponseAPDU;
import org.bouncycastle.jce.ECPointUtil;

import java.security.KeyPair;
import java.security.Signature;
import java.security.KeyFactory;
import java.security.spec.ECPoint;
import java.security.KeyPairGenerator;
import java.security.SignatureException;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.ECParameterSpec;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.InvalidAlgorithmParameterException;

/**
 * Cryptographie
 */
public final class Crypto {
	
	private Crypto() {}
	
	public static byte[] getByteArrayFromPublicKey(ECPublicKey publicKey) {
		BigInteger x = publicKey.getW().getAffineX();
		BigInteger y = publicKey.getW().getAffineY();		
		byte[] xBytes = x.toByteArray();
		byte[] yBytes = y.toByteArray();
		
		byte[] byteArray = new byte[65];
		
		byteArray[0] = 0x04;
		
		try {
			System.arraycopy(xBytes, xBytes[0] == 0x00 ? 1 : 0, byteArray, 1, 32);
			System.arraycopy(yBytes, yBytes[0] == 0x00 ? 1 : 0, byteArray, 33, 32);
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println(Util.bytesToHex(xBytes));
			System.out.println(Util.bytesToHex(yBytes));
			System.out.println(e.getMessage());
			System.out.println(Util.bytesToHex(byteArray));
		}
		
		return byteArray;
	}
	
	public static KeyPair generateKeyPair() {
		KeyPairGenerator keyGen = null;
		try {
			keyGen = KeyPairGenerator.getInstance("EC");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Une erreur inattendue s'est produite." + e.getMessage());
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);					
		}
		
		ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
		try {
			keyGen.initialize(ecSpec);
		} catch (InvalidAlgorithmParameterException e) {
			System.out.println("Une erreur inattendue s'est produite." + e.getMessage());
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);					
		}
		
		return keyGen.generateKeyPair();
	}
	
	
	public static byte[] signMessage(Signature signatureObject, byte[] message) {
		byte[] signature = new byte[] {};
		
		try {
			signatureObject.update(message);
		} catch (SignatureException e) {
			System.out.println("Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);					
		}
		
		try {
			signature = signatureObject.sign();
		} catch (SignatureException e) {
			System.out.println("Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);					
		}
		
		return signature;
	}
	
	public static boolean verifyResponseApduSignature(Signature signatureObject, ResponseAPDU response, int signatureOffset) {
		byte[] plainText = getPlainTextAssociatedWithSignature(response, signatureOffset);
		byte[] signature = getDerEncodedSignature(response, signatureOffset);
	     return verifySignature(signatureObject, plainText, signature);
	}
	
	public static boolean verifySignature(Signature signatureObject, byte[] plainText, byte[] signature) {		
		boolean isValid = false;
	      try {
			signatureObject.update(plainText);
		} catch (SignatureException e) {
			System.out.println("Erreur " + e.getMessage());
		}
	      
	     try {
			isValid = signatureObject.verify(signature);
		} catch (SignatureException e) {
			System.out.println("Erreur " + e.getMessage());
		}
	     
	     return isValid;
	}

	
	public static ECPublicKey getPublicKeyFromByteArray(byte[] publicKeyByteArray) {	
		ECPublicKey ecPublicKey = null;
		AlgorithmParameters algorithmParameters = null;
		ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
		
		try {
			algorithmParameters = AlgorithmParameters.getInstance("EC");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);					
		}
		
		try {
			algorithmParameters.init(ecGenParameterSpec);
		} catch (InvalidParameterSpecException e) {
			System.out.println("Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);					
		}
		
		ECParameterSpec ecParameterSpec = null;
		try {
			ecParameterSpec = algorithmParameters.getParameterSpec(ECParameterSpec.class);
		} catch (InvalidParameterSpecException e) {
			System.out.println("Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);					
		}
		
		ECPoint ecPoint = ECPointUtil.decodePoint(ecParameterSpec.getCurve(), publicKeyByteArray);
		KeyFactory keyFactory = null;
		try {
			keyFactory = KeyFactory.getInstance("EC");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);
		try {
			ecPublicKey = (ECPublicKey) keyFactory.generatePublic(ecPublicKeySpec);
		} catch (InvalidKeySpecException e) {
			System.out.println("Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		return ecPublicKey;
	}
	
	public static byte[] getPlainTextAssociatedWithSignature(ResponseAPDU response, int signatureOffset) {
		byte[] responseBuffer = response.getData();
		byte[] buffer = new byte[signatureOffset];
		
		// void java.lang.System.arraycopy(Object src, int srcPos, Object dest, int destPos, int length)
		System.arraycopy(responseBuffer, 0, buffer, 0, signatureOffset);
		return buffer;
	}
	
	
	public static byte[] getEncodedSignatureForJavaCard(byte[] signature) {
		byte[] encodedSignature = signature;
		if (signature.length >= 70) {
			encodedSignature = new byte[64];
			
			//  signature[0] => signature[3] : 0x30  0x44  0x02  0x20 
			int rStartCopie = 4;
			int rLength = signature[3];
			
			if (rLength > 32 && signature[rStartCopie] == 0x00) {
				rStartCopie++;
				rLength = 32;
			}
			
			// void java.lang.System.arraycopy(Object src, int srcPos, Object dest, int destPos, int length)
			System.arraycopy(signature, rStartCopie, encodedSignature, 0, rLength);

			//  signature[rStartCopie + rLength] => signature[rStartCopie + rLength + 1] : 0x02  0x20
			int sStartCopie = rStartCopie + rLength + 2;
			int sLength = signature[rStartCopie + rLength + 1];
			if (sLength > 32 && signature[sStartCopie] == 0x00) {
				sStartCopie++;
				sLength = 32;
			}

			// void java.lang.System.arraycopy(Object src, int srcPos, Object dest, int destPos, int length)
			System.arraycopy(signature, sStartCopie, encodedSignature, rLength, sLength);			
		}
		
		return encodedSignature;
	}

	
	public static byte[] getDerEncodedSignature(ResponseAPDU response, int signatureOffset) {
		byte[] responseBuffer = response.getData();
		
		int responseBufferIndex = signatureOffset;
		
		boolean rAbove7f = responseBuffer[signatureOffset] > 0x7F || responseBuffer[signatureOffset] < 0;
		boolean sAbove7f = responseBuffer[signatureOffset + 32] > 0x7F || responseBuffer[signatureOffset + 32] < 0;
		
		byte[] signature = new byte[70 + (rAbove7f ? 1 : 0)  + (sAbove7f ? 1 : 0)];
		signature[0] = 0x30;
		signature[1] = (byte) (0x44 + (rAbove7f ? 0x01 : 0x00)  + (sAbove7f ? 0x01 : 0x00));
		signature[2] = 0x02;
		signature[3] = (byte) (0x20 + (rAbove7f ? 0x01 : 0x00));
		
		int rStartIndex = 4;
		if (rAbove7f) {
			signature[rStartIndex] = 0x00;
			rStartIndex++;
		}
		for(int i = rStartIndex; i < rStartIndex + 32; i++,responseBufferIndex++) {
			signature[i] = (byte) responseBuffer[responseBufferIndex];
		}
		
		int sStartIndex = rStartIndex + 32 + 2;
		if (sAbove7f) {
			signature[sStartIndex] = 0x00;
			sStartIndex++;
		}

		signature[rStartIndex + 32] = 0x02;
		signature[rStartIndex + 32 + 1] = (byte) (0x20 + (sAbove7f ? 0x01 : 0x00));
		for(int i = sStartIndex ; i < sStartIndex + 32; i++,responseBufferIndex++) {
			signature[i] = (byte) responseBuffer[responseBufferIndex];
		}

		return signature;
	}
	
	public static Signature setSignatureAlgorithm() {
		Signature signatureObject;
		
		try {
			signatureObject = Signature.getInstance("SHA256withECDSA"); // secp256r1			
		} catch (NoSuchAlgorithmException e) {
			signatureObject = null;
		}
		
		return signatureObject;
	}
	
	public static boolean signatureInitSign(Signature signatureObject, ECPrivateKey privateKey) {
		boolean operationResult = true;
		
	    try {
	    	signatureObject.initSign(privateKey);
		} catch (InvalidKeyException e) {
			operationResult = false;
		}				    
	      
	    return operationResult;
	}
	
	public static boolean signatureInitVerify(Signature signatureObject, ECPublicKey publicKey) {
		boolean operationResult = true;
		
	    try {
	    	signatureObject.initVerify(publicKey); 
		} catch (InvalidKeyException e) {
			operationResult = false;
		}				    
	      
	    return operationResult;
	}
}