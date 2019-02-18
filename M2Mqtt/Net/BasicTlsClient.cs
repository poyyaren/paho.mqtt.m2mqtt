using Org.BouncyCastle.Crypto.Tls;

namespace uPLibrary.Networking.M2Mqtt.Net
{
#if COMPACT_FRAMEWORK
    internal class BasicTlsClient : DefaultTlsClient
    {
        public override TlsAuthentication GetAuthentication()
        {
            return new NoTlsAuthentication();
        }
    }
#endif
}