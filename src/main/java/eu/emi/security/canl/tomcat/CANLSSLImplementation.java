/*
 * Copyright (c) 2012 Helsinki Institute of Physics All rights reserved.
 * See LICENCE file for licensing information.
 */

package eu.emi.security.canl.tomcat;

import java.io.InputStream;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.tomcat.util.net.AbstractEndpoint;
import org.apache.tomcat.util.net.ServerSocketFactory;
import org.apache.tomcat.util.net.jsse.JSSEImplementation;

/**
 * 
 * Created on 2012-06-13
 * 
 * @author Joni Hahkala
 */
public class CANLSSLImplementation
    extends JSSEImplementation {

    private static final Logger logger = Logger.getLogger(CANLSSLImplementation.class.getCanonicalName());

    /**
     * The constructor for the class, does nothing except checks that the actual ssl implementation TrustManager is
     * present.
     * 
     * @throws ClassNotFoundException
     *             in case the util-java is not installed and thus ContextWrapper class isn't found.
     */
    public CANLSSLImplementation() throws ClassNotFoundException {

        InputStream in = null;
        Properties props = null;
        try {
            in = this.getClass().getClassLoader()
                    .getResourceAsStream("META-INF/maven/eu.eu-emi.security/canl-java-tomcat/pom.properties");
            props = new Properties();
            props.load(in);
            String canlTomcatVersion = props.getProperty("version");
            logger.info("Tomcat pluging version " + canlTomcatVersion + " starting.");
        } catch (Exception e) {
            logger.log(Level.SEVERE,
                    "Canl tomcat plugin starting, version information loading failed: " + e.getMessage(), e);
        }
        try {
            in = this.getClass().getClassLoader()
                    .getResourceAsStream("META-INF/maven/eu.eu-emi.security/canl/pom.properties");
            props = new Properties();
            props.load(in);
            String canlVersion = props.getProperty("version");
            logger.info("CANL version " + canlVersion + " starting.");
        } catch (Exception e) {
            boolean oldSuccess = false;
            try {
                in = this.getClass().getClassLoader()
                        .getResourceAsStream("META-INF/maven/eu.emi.security/canl/pom.properties");
                props = new Properties();
                props.load(in);
                String canlVersion = props.getProperty("version");
                logger.info("CANL version " + canlVersion + " starting.");
                oldSuccess = true;
            } catch (Exception ex) {
                // ignore failure in fallback
            }
            if (!oldSuccess) {
                logger.log(Level.SEVERE,
                        "Canl tomcat plugin starting, canl version information loading failed: " + e.getMessage(), e);
            }
        }
        // Check to see if canl is floating around
        // somewhere, will fail if it is not found throwing
        // an exception, this forces early failure in case there is no hope of
        // it working anyway.
        Class.forName("eu.emi.security.authn.x509.CommonX509TrustManager");
    }

    /*
     * The Method that returns the name of the SSL implementation
     * 
     * The string "TM-SSL" is returned (shorthand for TrustManager SSL)
     * 
     * @see org.apache.tomcat.util.net.SSLImplementation#getImplementationName()
     */
    @Override
    public String getImplementationName() {
        return "CANL-SSL";
    }

    @Override
    public ServerSocketFactory getServerSocketFactory(AbstractEndpoint endpoint) {
        return new CANLSSLServerSocketFactory(endpoint);
    }

}
