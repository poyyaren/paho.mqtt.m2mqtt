using Org.BouncyCastle.Crypto.Tls;

namespace uPLibrary.Networking.M2Mqtt.Net
{
#if COMPACT_FRAMEWORK
    internal class NoTlsAuthentication : TlsAuthentication
    {
        // TODO: implement RemoteCertificateValidationCallback alternative
        public void NotifyServerCertificate(Certificate serverCertificate)
        {
        }

        // TODO: implement LocalCertificateSelectionCallback alternative
        public TlsCredentials GetClientCredentials(CertificateRequest certificateRequest)
        {
            return null;
        }
    }
#endif
}