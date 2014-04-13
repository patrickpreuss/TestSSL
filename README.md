Test SSL
--------

A cosmetic facade around the [TestSSLServer by Thomas Pornin](http://www.bolet.org/TestSSLServer/) so that it can be used as a library from other Java apps.

Heartbleed test taken from Colm O'Flaherty's active scanner test for OWASP ZAP proxy: https://code.google.com/p/zaproxy/

Instead of printing out the results, it populates internal variables, usage is:
```Java

        TestSSL testSSL = new TestSSL();
        testSSL.test("www.example.com", 443);

        System.out.println("Supported protocols:");
        for (String protocol : testSSL.getSupportedProtocols()) {
            System.out.println(protocol);
        }
        
        System.out.println("Supported ciphers:");
        for (String key : testSSL.getSupportedCiphers().keySet()) {
            System.out.println("  "+key);
            for (String cipher : testSSL.getSupportedCiphers().get(key)) {
                System.out.println("   "+cipher);
            }
        }
        System.out.println("Vulnerable to BEAST: "+testSSL.isVulnBEAST());
        System.out.println("Vulnerable to CRIME: "+testSSL.isVulnCRIME());
        System.out.println("Vulnerable to Heartbleed: " + testSSL.isVulnHeartbleed() + " protocols: " + testSSL.getHeartbleedDetails());
        System.out.println("Minimum encryption strength [0-3]: "+testSSL.getMinEncryptionStrength());
        System.out.println("Maximum encryption strength [0-3]: "+testSSL.getMaxEncryptionStrength());

```
  
Warning
-------
This library is provided without any warranty of any kind.
