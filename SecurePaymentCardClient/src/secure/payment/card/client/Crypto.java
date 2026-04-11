package secure.payment.card.client;

import java.util.Date;
import java.math.BigInteger;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.IllegalBlockSizeException;

import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;

import java.security.Key;
import java.security.KeyPair;
import java.security.Signature;
import java.security.KeyFactory;
import java.security.PrivateKey;
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

import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

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
			// void java.lang.System.arraycopy( Object src, int srcPos, Object dest, int destPos, int length)
			System.arraycopy(xBytes, xBytes[0] == 0x00 ? 1 : 0, byteArray, 1, 32);
			System.arraycopy(yBytes, yBytes[0] == 0x00 ? 1 : 0, byteArray, 33, 32);
			System.out.println(Util.bytesToHex(xBytes));
			System.out.println(Util.bytesToHex(yBytes));
			System.out.println(Util.bytesToHex(byteArray));
			System.out.println(xBytes.length);
			System.out.println(yBytes.length);

		} catch (Exception e) {
			e.printStackTrace();
			System.out.println(Util.bytesToHex(xBytes));
			System.out.println(Util.bytesToHex(yBytes));
			System.out.println(e.getMessage());
			System.out.println(Util.bytesToHex(byteArray));
			System.out.println(xBytes.length);
			System.out.println(yBytes.length);
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
	
	public static boolean verifyResponseApduSignature(Signature signatureObject, byte[] responseBuffer, int signatureOffset) {
		byte[] plainText = getPlainTextAssociatedWithSignature(responseBuffer, signatureOffset);
		byte[] signature = getDerEncodedSignature(responseBuffer, signatureOffset);
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
	
	public static byte[] getPlainTextAssociatedWithSignature(byte[] responseBuffer, int signatureOffset) {
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

	
	public static byte[] getDerEncodedSignature(byte[] responseBuffer, int signatureOffset) {		
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
	
	public static byte[] generateSharedSecret(ECPublicKey cardPublicKey, PrivateKey privateKey) {
	    KeyAgreement keyAgreement = null;
		
	    try {
			keyAgreement = KeyAgreement.getInstance("ECDH");
		} catch (NoSuchAlgorithmException e) {
			return null;
		}
		
	    try {
			keyAgreement.init(privateKey);
		} catch (InvalidKeyException e) {
			return null;
		}
	    
	    try {
			keyAgreement.doPhase(cardPublicKey, true);
		} catch (InvalidKeyException e) {
			return null;
		} catch (IllegalStateException e) {
			return null;
		}
	    
	    return keyAgreement.generateSecret();
	}
	
	public static Key createAesKey(byte[] key, int offset, int len) {
		return new SecretKeySpec(key, offset, len, "AES/ECB/PKCS5Padding");
	}
	
	public static Cipher initCipherObject(int opMode, Key aesKey) {
		Cipher cipherObject = null;
		
        try {
        	cipherObject = Cipher.getInstance("AES/ECB/PKCS5Padding");
		} catch (NoSuchAlgorithmException e) {
			
		} catch (NoSuchPaddingException e) {
			
		}
	        
        try {
        	cipherObject.init(opMode, aesKey);
		} catch (InvalidKeyException e) {
		}
        
        return cipherObject;
	}
	
	public static byte[] cipherObjectDoFinal(Cipher cipherObject, byte[] value) {
		byte[] result = null;
		
        try {
        	result = cipherObject.doFinal(value);
		} catch (IllegalBlockSizeException e) {
			System.out.println("IllegalBlockSizeException " + e.getMessage());
		} catch (BadPaddingException e) {
			System.out.println("BadPaddingException " + e.getMessage());
		}
        
        return result;
	}
		
	public static byte[] decryptAes(Cipher cipherDecryptObject, byte[] encryptedData) {
		byte[] decryptedValue = cipherObjectDoFinal(cipherDecryptObject, encryptedData);		
        return decryptedValue;
	}
	
	public static byte[] encryptAes(Cipher cipherEncryptObject, byte[] decryptedValue) {
		byte[] encryptedData = cipherObjectDoFinal(cipherEncryptObject, decryptedValue);		
        return encryptedData;
	}
	
	public static KeyPair generateRsaKeyPair() {
        KeyPairGenerator keyPairGenerator = null;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
	          System.out.println(e.getMessage());
		}
        keyPairGenerator.initialize(2048, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
	}
	
	public static X509Certificate createSelfSignedCertificate(KeyPair keyPair) {	      
	      X500Principal distinguishedName = new X500Principal("CN=localhost");	      

	      long now = System.currentTimeMillis();
	      long validityPeriod = now + (1000L * 3600L * 24 * 365);

	      ASN1Encodable[] encodableAltNames = new ASN1Encodable[]{new GeneralName(GeneralName.dNSName, "localhost")};
	      KeyPurposeId[] purposes = new KeyPurposeId[]{KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth};

	      X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(distinguishedName,
	            BigInteger.ONE, new Date(now), new Date(validityPeriod), distinguishedName, keyPair.getPublic());
	      try {
	          certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
	          certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature + KeyUsage.keyEncipherment));
	          certBuilder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(purposes));
	          certBuilder.addExtension(Extension.subjectAlternativeName, false, new DERSequence(encodableAltNames));
	          
	          final ContentSigner signer = new JcaContentSignerBuilder(("SHA1withRSA")).build(keyPair.getPrivate());	          
	          return new JcaX509CertificateConverter()
	    	            .setProvider(new BouncyCastleProvider()).getCertificate(certBuilder.build(signer));
	       } catch (Exception e) {
	          System.out.println(e.getMessage());
	       }
	      return null;
	}
}