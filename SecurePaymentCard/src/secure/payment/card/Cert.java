package secure.payment.card;

import javacardx.security.cert.Certificate;
import javacardx.security.cert.X509Certificate;
import javacardx.security.cert.CertificateParser;
import javacardx.security.cert.CertificateException;
import javacardx.security.cert.X509Certificate.FieldHandler;
import javacardx.security.cert.X509Certificate.ExtensionHandler;

public class Cert implements FieldHandler, ExtensionHandler {
    private final CertificateParser parser = CertificateParser.getInstance(CertificateParser.TYPE_X509_DER);

    public Certificate buildCert(byte[] data, short offset, short length) throws CertificateException {
        return parser.buildCert(data, offset, length, this);
    }

    @Override
    public boolean onField(short fieldID, byte[] field) {
        switch (fieldID) {
        case X509Certificate.FIELD_TBS_ISSUER:    
        case X509Certificate.FIELD_TBS_NOT_AFTER: 
        case X509Certificate.FIELD_TBS_NOT_BEFORE:
        case X509Certificate.FIELD_TBS_SUBJECT:   
            return true;
        }

        return false;
    }

    @Override
    public boolean onExtension(byte[] oid, boolean isCritical, byte[] value) {
       return
          isCritical /* ||
          Util.arrayCompare(oid, (short)0, OID_SUBJECT_ALT_NAME, (short)0, OID_SUBJECT_ALT_NAME.length) == 0) */;
    }
}