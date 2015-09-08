/*
 * Copyright (c) 2012 Helsinki Institute of Physics All rights reserved.
 * See LICENCE file for licensing information.
 */

package eu.emi.security.canl.tomcat;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocket;

import org.apache.tomcat.util.net.AbstractEndpoint;
import org.apache.tomcat.util.net.jsse.JSSESocketFactory;

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.NamespaceCheckingMode;
import eu.emi.security.authn.x509.OCSPParametes;
import eu.emi.security.authn.x509.ProxySupport;
import eu.emi.security.authn.x509.RevocationParameters;
import eu.emi.security.authn.x509.RevocationParameters.RevocationCheckingOrder;
import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.ValidationError;
import eu.emi.security.authn.x509.ValidationErrorListener;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;
import eu.emi.security.authn.x509.impl.KeyAndCertCredential;
import eu.emi.security.authn.x509.impl.OpensslCertChainValidator;
import eu.emi.security.authn.x509.impl.SocketFactoryCreator;
import eu.emi.security.authn.x509.impl.ValidatorParams;

/**
 * The Tomcat glue ServerSocketFactory class. This class works as a glue interface that interfaces the TrustManager SSL
 * implementation with the Tomcat.
 * 
 * @author Joni Hahkala
 */
public class CANLSSLServerSocketFactory
    extends JSSESocketFactory {

    /** The internal serversocket instance. */
    // protected SSLServerSocketFactory _serverSocketFactory = null;

    private AbstractEndpoint endpoint;

    public CANLSSLServerSocketFactory(AbstractEndpoint endpoint) {
        super(endpoint);

        this.endpoint = endpoint;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.apache.tomcat.util.net.ServerSocketFactory#acceptSocket(java.net. ServerSocket)
     */
    public Socket acceptSocket(ServerSocket sSocket)
        throws IOException {

        SSLSocket asock = null;

        try {
            asock = (SSLSocket) sSocket.accept();
            configureClientAuth(asock);
            String ip = asock.getInetAddress().toString();
            System.out.println(new Date().toString() + " : connection from " + ip);
        } catch (SSLException e) {
            throw new SocketException("SSL handshake error" + e.toString());
        }

        return asock;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.apache.tomcat.util.net.ServerSocketFactory#createSocket(int, int, java.net.InetAddress)
     */
    @Override
    public ServerSocket createSocket(int port, int backlog, InetAddress ifAddress)
        throws IOException {

        if (sslProxy == null) {
            initServerSocketFactory();
        }
        ServerSocket socket = sslProxy.createServerSocket(port, backlog, ifAddress);
        initServerSocket(socket);

        return socket;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.apache.tomcat.util.net.ServerSocketFactory#createSocket(int, int)
     */
    @Override
    public ServerSocket createSocket(int port, int backlog)
        throws IOException {

        if (sslProxy == null) {
            initServerSocketFactory();
        }
        ServerSocket socket = sslProxy.createServerSocket(port, backlog);
        initServerSocket(socket);

        return socket;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.apache.tomcat.util.net.ServerSocketFactory#createSocket(int)
     */
    @Override
    public ServerSocket createSocket(int port)
        throws IOException {

        if (sslProxy == null) {
            initServerSocketFactory();
        }
        ServerSocket socket = sslProxy.createServerSocket(port);
        initServerSocket(socket);

        return socket;
    }

    /**
     * Initialize the SSL socket factory.
     * 
     * @exception IOException
     *                if an input/output error occurs
     */
    private void initServerSocketFactory()
        throws IOException {

        String clientAuthStr = endpoint.getClientAuth();
        if ("true".equalsIgnoreCase(clientAuthStr) || "yes".equalsIgnoreCase(clientAuthStr)) {
            requireClientAuth = true;
        } else if ("want".equalsIgnoreCase(clientAuthStr)) {
            wantClientAuth = true;
        }

        /*
         * This section contains the customization of the context using CAnL
         */
        StoreUpdateListener listener = new StoreUpdateListener() {
            public void loadingNotification(String location, String type, Severity level, Exception cause) {
                if (level != Severity.NOTIFICATION) {
                    System.out.println("Error when creating or using SSL socket. Type " + type + " level: " + level
                            + ((cause == null) ? "" : (" cause: " + cause.getClass() + ":" + cause.getMessage())));
                } else {
                    // log successful (re)loading
                }
            }
        };

        ArrayList<StoreUpdateListener> listenerList = new ArrayList<StoreUpdateListener>();
        listenerList.add(listener);

        RevocationParameters revParam = new RevocationParameters(CrlCheckingMode.REQUIRE, new OCSPParametes(), false,
                RevocationCheckingOrder.CRL_OCSP);
        String crlCheckingMode = (String) endpoint.getAttribute("crlcheckingmode");
        if (crlCheckingMode != null) {
            if (crlCheckingMode.equalsIgnoreCase("ifvalid")) {
                revParam = new RevocationParameters(CrlCheckingMode.IF_VALID, new OCSPParametes(), false,
                        RevocationCheckingOrder.CRL_OCSP);
            }
            if (crlCheckingMode.equalsIgnoreCase("ignore")) {
                revParam = new RevocationParameters(CrlCheckingMode.IGNORE, new OCSPParametes(), false,
                        RevocationCheckingOrder.CRL_OCSP);
            }
        }

        ProxySupport proxySupport = ProxySupport.ALLOW;
        String proxySupportString = (String) endpoint.getAttribute("proxysupport");
        if (proxySupportString != null) {
            if (proxySupportString.equalsIgnoreCase("no") || proxySupportString.equalsIgnoreCase("false")) {
                proxySupport = ProxySupport.DENY;
            }
        }

        ValidatorParams validatorParams = new ValidatorParams(revParam, proxySupport, listenerList);

        String trustStoreLocation = (String) endpoint.getAttribute("truststore");
        if (trustStoreLocation == null) {
            throw new IOException("No truststore defined, unable to load CA certificates and thus create SSL socket.");
        }

        String namespaceModeString = (String) endpoint.getAttribute("namespace");
        NamespaceCheckingMode namespaceMode = NamespaceCheckingMode.EUGRIDPMA_AND_GLOBUS;
        if (namespaceModeString != null) {
            if (namespaceModeString.equalsIgnoreCase("no") || namespaceModeString.equalsIgnoreCase("false")
                    || namespaceModeString.equalsIgnoreCase("off")) {
                namespaceMode = NamespaceCheckingMode.IGNORE;
            } else {
                if (namespaceModeString.equalsIgnoreCase("require")) {
                    namespaceMode = NamespaceCheckingMode.EUGRIDPMA_AND_GLOBUS_REQUIRE;
                }
            }

        }

        String intervalString = (String) endpoint.getAttribute("updateinterval");
        long intervalMS = 3600000; // update every hour
        if (intervalString != null) {
            intervalMS = Long.parseLong(intervalString);
        }

        OpensslCertChainValidator validator = new OpensslCertChainValidator(trustStoreLocation, namespaceMode,
                intervalMS, validatorParams);

        ValidationErrorListener validationListener = new ValidationErrorListener() {
            @Override
            public boolean onValidationError(ValidationError error) {
                System.out.println("Error when validating incoming certificate: " + error.getMessage() + " position: "
                        + error.getPosition() + " " + error.getParameters());
                X509Certificate chain[] = error.getChain();
                for (X509Certificate cert : chain) {
                    System.out.println(cert.toString());
                }
                return false;
            }

        };

        validator.addValidationListener(validationListener);

        String hostCertLoc = (String) endpoint.getAttribute("hostcert");
        if (hostCertLoc == null) {
            throw new IOException(
                    "Variable hostcert undefined, cannot start server with SSL/TLS without host certificate.");
        }
        java.security.cert.X509Certificate[] hostCertChain = CertificateUtils.loadCertificateChain(new FileInputStream(
                hostCertLoc), Encoding.PEM);

        String hostKeyLoc = (String) endpoint.getAttribute("hostkey");
        if (hostKeyLoc == null) {
            throw new IOException(
                    "Variable hostkey undefined, cannot start server with SSL/TLS without host private key.");
        }
        PrivateKey hostKey = CertificateUtils.loadPrivateKey(new FileInputStream(hostKeyLoc), Encoding.PEM, null);

        KeyAndCertCredential credentials;
        try {
            credentials = new KeyAndCertCredential(hostKey, hostCertChain);
        } catch (KeyStoreException e) {
            throw new IOException("Error while creating keystore: " + e + ": " + e.getMessage(), e);
        }

        SSLContext context = SocketFactoryCreator.getSSLContext(credentials, validator, new SecureRandom());

        /*
         * end of the customization
         */
        
        SSLSessionContext sessionContext = context.getServerSessionContext();
        if (sessionContext != null) {
            configureSessionContext(sessionContext);
        }

        sslProxy = context.getServerSocketFactory();

        enabledCiphers = getEnableableCiphers(context);
        enabledProtocols = getEnableableProtocols(context);

        allowUnsafeLegacyRenegotiation = "true".equals(endpoint.getAllowUnsafeLegacyRenegotiation());

    }

    /**
     * Configures the given SSL server socket with the requested cipher suites and need for client authentication.
     * 
     * @param ssocket
     *            the server socket to initialize.
     */
    private void initServerSocket(ServerSocket ssocket) {

        SSLServerSocket socket = (SSLServerSocket) ssocket;

        socket.setEnabledCipherSuites(enabledCiphers);
        socket.setEnabledProtocols(enabledProtocols);

        // we don't know if client auth is needed -
        // after parsing the request we may re-handshake
        configureClientAuth(socket);

    }

    /**
     * Configure whether the client authentication is wanted, needed or not.
     * 
     * @param socket
     *            The socket to configure
     */
    protected void configureClientAuth(SSLSocket socket) {
        String clientAuthStr = endpoint.getClientAuth();

        if (clientAuthStr == null) {
            return;
        }

        if ("true".equalsIgnoreCase(clientAuthStr) || "yes".equalsIgnoreCase(clientAuthStr)) {
            socket.setNeedClientAuth(true);
        }

        if ("want".equalsIgnoreCase(clientAuthStr)) {
            socket.setWantClientAuth(true);
        }
    }
}
