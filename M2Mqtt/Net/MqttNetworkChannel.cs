/*
Copyright (c) 2013, 2014 Paolo Patierno

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution. 

The Eclipse Public License is available at 
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at 
   http://www.eclipse.org/org/documents/edl-v10.php.

Contributors:
   Paolo Patierno - initial API and implementation and/or initial documentation
*/

#if SSL
#if (MF_FRAMEWORK_VERSION_V4_2 || MF_FRAMEWORK_VERSION_V4_3)
using Microsoft.SPOT.Net.Security;
#else
#if  COMPACT_FRAMEWORK

#else
using System.Net.Security;
using System.Security.Authentication;
#endif
#endif
#endif
using System.Net.Sockets;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System;
using System.Threading;


namespace uPLibrary.Networking.M2Mqtt
{
    /// <summary>
    /// Channel to communicate over the network
    /// </summary>
    public class MqttNetworkChannel : IMqttNetworkChannel
    {
#if !(MF_FRAMEWORK_VERSION_V4_2 || MF_FRAMEWORK_VERSION_V4_3 || COMPACT_FRAMEWORK)
        private readonly RemoteCertificateValidationCallback userCertificateValidationCallback;
        private readonly LocalCertificateSelectionCallback userCertificateSelectionCallback;
#endif

        // Connect handles
        private bool connectSuccessful = false;
		private readonly object connectLock = new object();
		private Exception connectException;
        private ManualResetEvent connectWait = new ManualResetEvent(false);

        // remote host information
        private string remoteHostName;
        private IPAddress remoteIpAddress;
        private int remotePort;

        // socket for communication
        private Socket socket;
        // using SSL
        private bool secure;

        // CA certificate (on client)
        private X509Certificate caCert;
        // Server certificate (on broker)
        private X509Certificate serverCert;
        // client certificate (on client)
        private X509Certificate clientCert;

        // SSL/TLS protocol version
        private MqttSslProtocols sslProtocol;

        /// <summary>
        /// Remote host name
        /// </summary>
        public string RemoteHostName { get { return this.remoteHostName; } }

        /// <summary>
        /// Remote IP address
        /// </summary>
        public IPAddress RemoteIpAddress { get { return this.remoteIpAddress; } }

        /// <summary>
        /// Remote port
        /// </summary>
        public int RemotePort { get { return this.remotePort; } }

#if SSL
        // SSL stream
        private SslStream sslStream;
#if (!MF_FRAMEWORK_VERSION_V4_2 && !MF_FRAMEWORK_VERSION_V4_3)
        private NetworkStream netStream;
#endif
#endif

        /// <summary>
        /// Data available on the channel
        /// </summary>
        public bool DataAvailable
        {
            get
            {
#if SSL
#if (MF_FRAMEWORK_VERSION_V4_2 || MF_FRAMEWORK_VERSION_V4_3)
                if (secure)
                    return this.sslStream.DataAvailable;
                else
                    return (this.socket.Available > 0);
#else
                if (secure)
                    return this.netStream.DataAvailable;
                else
                    return (this.socket.Available > 0);
#endif
#else
                return (this.socket.Available > 0);
#endif
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="remoteHostName">Remote Host name</param>
        /// <param name="remotePort">Remote port</param>
        /// <param name="secure">Using SSL</param>
        /// <param name="caCert">CA certificate</param>
        /// <param name="clientCert">Client certificate</param>
        /// <param name="sslProtocol">SSL/TLS protocol version</param>
        public MqttNetworkChannel(string remoteHostName, int remotePort, bool secure, X509Certificate caCert, X509Certificate clientCert, MqttSslProtocols sslProtocol)
        {
            IPAddress remoteIpAddress = null;
            try
            {
                // check if remoteHostName is a valid IP address and get it
                remoteIpAddress = IPAddress.Parse(remoteHostName);
            }
            catch
            {
            }

            // in this case the parameter remoteHostName isn't a valid IP address
            /* Checked in Connect function to ensure that host name resolution is 
             * correct for each connection attempt so checking here is no longer 
             * needed and otherwise might prevent construction of the mqtt client 
             * and delegator if the host name cant be resolved
             * 
            if (remoteIpAddress == null)
            {
                IPHostEntry hostEntry = null;

                try
                {
                    hostEntry = Dns.GetHostEntry(remoteHostName);
                }
                catch
                {
                    throw new Exception("No address found for the remote host name");
                }

                if ((hostEntry != null) && (hostEntry.AddressList.Length > 0))
                {
                    // check for the first address not null
                    // it seems that with .Net Micro Framework, the IPV6 addresses aren't supported and return "null"
                    int i = 0;
                    while (hostEntry.AddressList[i] == null) i++;
                    remoteIpAddress = hostEntry.AddressList[i];
                }
                else
                {
                    throw new Exception("No address found for the remote host name");
                }
            }
            */

            this.remoteHostName = remoteHostName;
            this.remoteIpAddress = remoteIpAddress;
            this.remotePort = remotePort;
            this.secure = secure;
            this.caCert = caCert;
            this.clientCert = clientCert;
            this.sslProtocol = sslProtocol;
#if !(MF_FRAMEWORK_VERSION_V4_2 || MF_FRAMEWORK_VERSION_V4_3 || COMPACT_FRAMEWORK)
            this.userCertificateValidationCallback = userCertificateValidationCallback;
            this.userCertificateSelectionCallback = userCertificateSelectionCallback;
#endif
        }

        /// <summary>
        /// Connect to remote server
        /// </summary>
        public void Connect()
        {
            this.remoteIpAddress = GetIPAddrFromHostName(this.remoteHostName);

            if (this.remoteIpAddress != null)
            {
			
            	connectWait.Reset();

                lock (connectLock)
                {

                    if (socket != null)
                    {
                        System.Diagnostics.Debug.WriteLine("TLS: CLOSE SOCKET ON CONNECT 1");
                        socket.Close();
                    }

                    connectException = null;

                    this.socket = new Socket(this.remoteIpAddress.GetAddressFamily(), SocketType.Stream, ProtocolType.Tcp);
                    this.socket.Blocking = true;
                    // try connection to the broker
                    this.socket.BeginConnect(new IPEndPoint(this.remoteIpAddress, this.remotePort), new AsyncCallback(CallBackMethod), this.socket);

                }

				if (connectWait.WaitOne(2000, false))
	            {
	                if (!connectSuccessful)
	                {
						if (connectException != null)
							throw connectException;
	                    else
	                        throw new SocketException();
	                }
	            }
	            else
	            {
	                //Prevent any exceptions from disconnecting after publish for porsche spec
	                lock (connectLock)
	                {
                        System.Diagnostics.Debug.WriteLine("TLS: CLOSE SOCKET ON CONNECT 2");
                        this.socket.Close();
	                }
	                throw new TimeoutException("TimeOut Exception");
	            }
            
#if SSL
            // secure channel requested
            if (secure)
            {
                // create SSL stream
#if (MF_FRAMEWORK_VERSION_V4_2 || MF_FRAMEWORK_VERSION_V4_3 || COMPACT_FRAMEWORK)
                this.sslStream = new SslStream(this.socket);
#else
                this.netStream = new NetworkStream(this.socket);
                this.sslStream = new SslStream(this.netStream, false, this.userCertificateValidationCallback, this.userCertificateSelectionCallback);
#endif

                // server authentication (SSL/TLS handshake)
#if (MF_FRAMEWORK_VERSION_V4_2 || MF_FRAMEWORK_VERSION_V4_3)
                this.sslStream.AuthenticateAsClient(this.remoteHostName,
                    this.clientCert,
                    new X509Certificate[] { this.caCert },
                    SslVerification.CertificateRequired,
                    MqttSslUtility.ToSslPlatformEnum(this.sslProtocol));
#else
#if (COMPACT_FRAMEWORK)

#else
                X509CertificateCollection clientCertificates = null;
                // check if there is a client certificate to add to the collection, otherwise it's null (as empty)
                if (this.clientCert != null)
                    clientCertificates = new X509CertificateCollection(new X509Certificate[] { this.clientCert });

                this.sslStream.AuthenticateAsClient(this.remoteHostName,
                    clientCertificates,
                    MqttSslUtility.ToSslPlatformEnum(this.sslProtocol),
                    false);
   
#endif             
#endif
            }
#endif
            }
            else
            {
                throw new Exception("No address found for the remote host name");
            }

        }

        private void CallBackMethod(IAsyncResult asyncresult)
        {
            //Prevent any exceptions from disconnecting after publish for porsche spec
            lock (connectLock)
            {
                try
                {
                    connectSuccessful = false;
                    Socket socket = asyncresult.AsyncState as Socket;

                    if (CheckConnection(socket, true, true))
                    {
                        socket.EndConnect(asyncresult);
						connectSuccessful = true;
                    }                
                }
                catch (Exception ex)
                {
                    connectSuccessful = false;
                    connectException = ex;
                }
                finally
                {
                    connectWait.Set();
                }
            }                        
        }

        /// <summary>
        /// Checks if the connection is active on the specified socket
        /// </summary>
        /// <param name="socket">The socket to check the connection</param>
        /// <param name="checkForReading">Set true if check should be performed for reading or false for writing</param>
        /// <param name="closeSocketOnDisconnected">Set true if socket should be close if connection is not established</param>
        /// <returns><c>True</c> if the connection is active; otherwise <c>false</c></returns>
        protected bool CheckConnection(Socket socket, bool checkForReading, bool closeSocketOnDisconnected)
        {

            try
            {

                if (socket == null)
                {
                    // Socket to assigned => connection is not active
                    return false;
                }
                else if (socket.ProtocolType == ProtocolType.Tcp &&
                         !socket.Connected)
                {
                    // Connection is closed => connection is not active
                    if (closeSocketOnDisconnected)
                    {
                        CloseSocket(socket);
                    }
                    return false;
                }
                else if (checkForReading &&
                         socket.Poll(0, SelectMode.SelectRead))
                {

                    // true if Listen has been called and a connection is pending; 
                    // -or- 
                    // true if data is available for reading; 
                    // -or- 
                    // true if the connection has been closed, reset, or terminated; 
                    // otherwise, returns false.

                    if (socket.Available > 0)
                    {
                        // Data is available => connection is active
                        return true;
                    }
                    else if (socket.Poll(0, SelectMode.SelectError))
                    {
                        // We have a error... => connection might be not active
                        if (closeSocketOnDisconnected)
                        {
                            CloseSocket(socket);
                        }
                        return false;
                    }
                    else
                    {
                        // We have no error and no data but the connection should be active
                        return true;
                    }

                }
                else if (!checkForReading &&
                         socket.Poll(0, SelectMode.SelectWrite))
                {

                    // true, if processing a Connect, and the connection has succeeded; 
                    // -or- 
                    // true if data can be sent; 
                    // otherwise, returns false. 

                    if (socket.Poll(0, SelectMode.SelectError))
                    {
                        // We have a error... => connection might be not active
                        if (closeSocketOnDisconnected)
                        {
                            CloseSocket(socket);
                        }
                        return false;
                    }
                    else
                    {
                        // We have no error so the connection should be active
                        return true;
                    }

                }              
                else if (socket.Poll(0, SelectMode.SelectError))
                {
                    // We have a error... => connection might be not active
                    if (closeSocketOnDisconnected)
                    {
                        CloseSocket(socket);
                    }
                    return false;
                }               
                else
                {
                    // Socket not readable => we e.g. receive data => connection is active
                    return true;
                }

            }
            catch (Exception)
            {
                // Error occured => Connection problem (might occure if adapter is disposed => ok in that case)
                if (closeSocketOnDisconnected)
                {
                    CloseSocket(socket);
                }
                return false;
            }

        }

        /// <summary>
        /// Closes the passed socket gracefully
        /// </summary>
        /// <param name="socket">The socket to close</param>
        protected virtual void CloseSocket(Socket socket)
        {

            //try
            //{
            if (socket != null)
            {
                if (socket.Connected)
                {
                    socket.Shutdown(SocketShutdown.Both);
                }
                socket.Close();
                //EventLogger.LogEventSmart(EventLogger.DebugLevels.COMMUNICATION_ADAPTER, this, () => "{0}: Communication socket closed ({1})", name, endPointInfo);
            }
            /*}
            catch (Exception e)
            {
                // Should never happen...
                //EventLogger.LogEventSmart(EventLogger.DebugLevels.COMMUNICATION_ADAPTER_WARNINGS, this, () => "{0}: Error during closing socket: {1}", name, e.Message);
            }*/

        }

        /// <summary>
        /// Send data on the network channel
        /// </summary>
        /// <param name="buffer">Data buffer to send</param>
        /// <returns>Number of byte sent</returns>
        public int Send(byte[] buffer)
        {
#if SSL
            if (this.secure)
            {
                this.sslStream.Write(buffer, 0, buffer.Length);
                this.sslStream.Flush();
                return buffer.Length;
            }
            else
                return this.socket.Send(buffer, 0, buffer.Length, SocketFlags.None);
#else
            return this.socket.Send(buffer, 0, buffer.Length, SocketFlags.None);
#endif
        }

        /// <summary>
        /// Gets an IP Address from a remote hostname string
        /// </summary>
        /// <param name="hostName">Hostname to get an IP Address for</param>
        /// <returns>The IP Address of the remote hostname</returns>
        private IPAddress GetIPAddrFromHostName(string hostName)
        {
            IPAddress tempIP = null;
            IPHostEntry hostEntry = null;
            try
            {
                // check if remoteHostName is a valid IP address and get it
                tempIP = IPAddress.Parse(hostName);
            }
            catch
            {               
            }

            // in this case the parameter remoteHostName isn't a valid IP address
            if (tempIP == null)
            {
                try
                {

                    hostEntry = Dns.GetHostEntry(hostName);
                }
                catch
                {
                    throw new Exception("No address found for the remote host name");
                }

                if ((hostEntry != null) && (hostEntry.AddressList.Length > 0))
                {
                    // check for the first address not null
                    // it seems that with .Net Micro Framework, the IPV6 addresses aren't supported and return "null"
                    int i = 0;
                    while (hostEntry.AddressList[i] == null) i++;
                    tempIP = hostEntry.AddressList[i];
                }
                else
                {
                    throw new Exception("No address found for the remote host name");
                }
            }

            return tempIP;
        }

        /// <summary>
        /// Receive data from the network
        /// </summary>
        /// <param name="buffer">Data buffer for receiving data</param>
        /// <returns>Number of bytes received</returns>
        public int Receive(byte[] buffer)
        {
#if SSL
            if (this.secure)
            {
                // read all data needed (until fill buffer)
                int idx = 0, read = 0;
                while (idx < buffer.Length)
                {
                    // fixed scenario with socket closed gracefully by peer/broker and
                    // Read return 0. Avoid infinite loop.
                    read = this.sslStream.Read(buffer, idx, buffer.Length - idx);
                    if (read == 0)
                        return 0;
                    idx += read;
                }
                return buffer.Length;
            }
            else
            {
                // read all data needed (until fill buffer)
                int idx = 0, read = 0;
                while (idx < buffer.Length)
                {
                    // fixed scenario with socket closed gracefully by peer/broker and
                    // Read return 0. Avoid infinite loop.
                    read = this.socket.Receive(buffer, idx, buffer.Length - idx, SocketFlags.None);
                    if (read == 0)
                        return 0;
                    idx += read;
                }
                return buffer.Length;
            }
#else
            // read all data needed (until fill buffer)
            int idx = 0, read = 0;
            while (idx < buffer.Length)
            {
                // fixed scenario with socket closed gracefully by peer/broker and
                // Read return 0. Avoid infinite loop.
                read = this.socket.Receive(buffer, idx, buffer.Length - idx, SocketFlags.None);
                if (read == 0)
                    return 0;
                idx += read;
            }
            return buffer.Length;
#endif
        }

        /// <summary>
        /// Receive data from the network channel with a specified timeout
        /// </summary>
        /// <param name="buffer">Data buffer for receiving data</param>
        /// <param name="timeout">Timeout on receiving (in milliseconds)</param>
        /// <returns>Number of bytes received</returns>
        public int Receive(byte[] buffer, int timeout)
        {
            // check data availability (timeout is in microseconds)
            if (this.socket.Poll(timeout * 1000, SelectMode.SelectRead))
            {
                return this.Receive(buffer);
            }
            else
            {
                return 0;
            }
        }

        /// <summary>
        /// Close the network channel
        /// </summary>
        public void Close()
        {
            lock (connectLock)
            {
#if SSL
            if (this.secure)
            {
#if (!MF_FRAMEWORK_VERSION_V4_2 && !MF_FRAMEWORK_VERSION_V4_3)
                this.netStream.Close();
#endif
                this.sslStream.Close();
            }
            this.socket.Close();
#else
                System.Diagnostics.Debug.WriteLine("TLS: CLOSE SOCKET EXTERNAL");

                this.socket.Close();
#endif
            }
        }

        /// <summary>
        /// Accept connection from a remote client
        /// </summary>
        public void Accept()
        {
#if SSL
            // secure channel requested
            if (secure)
            {

#if !(MF_FRAMEWORK_VERSION_V4_2 || MF_FRAMEWORK_VERSION_V4_3 || COMPACT_FRAMEWORK)

                this.netStream = new NetworkStream(this.socket);
                this.sslStream = new SslStream(this.netStream, false, this.userCertificateValidationCallback, this.userCertificateSelectionCallback);

                this.sslStream.AuthenticateAsServer(this.serverCert, false, MqttSslUtility.ToSslPlatformEnum(this.sslProtocol), false);
#endif
            }

            return;
#else
            return;
#endif
        }
    }

    /// <summary>
    /// IPAddress Utility class
    /// </summary>
    public static class IPAddressUtility
    {
        /// <summary>
        /// Return AddressFamily for the IP address
        /// </summary>
        /// <param name="ipAddress">IP address to check</param>
        /// <returns>Address family</returns>
        public static AddressFamily GetAddressFamily(this IPAddress ipAddress)
        {
#if (!MF_FRAMEWORK_VERSION_V4_2 && !MF_FRAMEWORK_VERSION_V4_3)
            return ipAddress.AddressFamily;
#else
            return (ipAddress.ToString().IndexOf(':') != -1) ? 
                AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
#endif
        }
    }

    /// <summary>
    /// MQTT SSL utility class
    /// </summary>
    public static class MqttSslUtility
    {
#if (!MF_FRAMEWORK_VERSION_V4_2 && !MF_FRAMEWORK_VERSION_V4_3 && !COMPACT_FRAMEWORK)
        public static SslProtocols ToSslPlatformEnum(MqttSslProtocols mqttSslProtocol)
        {
            switch (mqttSslProtocol)
            {
                case MqttSslProtocols.None:
                    return SslProtocols.None;
                case MqttSslProtocols.SSLv3:
                    return SslProtocols.Ssl3;
                case MqttSslProtocols.TLSv1_0:
                    return SslProtocols.Tls;
                //case MqttSslProtocols.TLSv1_1:
                //    return SslProtocols.Tls11;
                //case MqttSslProtocols.TLSv1_2:
                //    return SslProtocols.Tls12;
                default:
                    throw new ArgumentException("SSL/TLS protocol version not supported");
            }
        }
#elif (MF_FRAMEWORK_VERSION_V4_2 || MF_FRAMEWORK_VERSION_V4_3)
        public static SslProtocols ToSslPlatformEnum(MqttSslProtocols mqttSslProtocol)
        {
            switch (mqttSslProtocol)
            {
                case MqttSslProtocols.None:
                    return SslProtocols.None;
                case MqttSslProtocols.SSLv3:
                    return SslProtocols.SSLv3;
                case MqttSslProtocols.TLSv1_0:
                    return SslProtocols.TLSv1;
                case MqttSslProtocols.TLSv1_1:
                case MqttSslProtocols.TLSv1_2:
                default:
                    throw new ArgumentException("SSL/TLS protocol version not supported");
            }
        }
#elif (FRAMEWORK_V4)
		public static SslProtocols ToSslPlatformEnum(MqttSslProtocols mqttSslProtocol)
		{
			switch (mqttSslProtocol)
			{
				case MqttSslProtocols.None:
					return SslProtocols.None;
				case MqttSslProtocols.SSLv3:
					return SslProtocols.Ssl3;
				case MqttSslProtocols.TLSv1_0:
					return SslProtocols.Tls;
				case MqttSslProtocols.TLSv1_1:
				case MqttSslProtocols.TLSv1_2:
				default:
					throw new ArgumentException("SSL/TLS protocol version not supported");
			}
		}
#endif
	}
}