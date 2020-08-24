Java.perform(function() {
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    var ArrayList = Java.use("java.util.ArrayList");
    TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain,
        host, clientAuth, ocspData, tlsSctData) {
        console.log("[+] Bypassing TrustManagerImpl->verifyChain()");
        return untrustedChain;
    }
    TrustManagerImpl.checkTrustedRecursive.implementation = function(certs, host, clientAuth, untrustedChain,
        trustAnchorChain, used) {
        console.log("[+] Bypassing TrustManagerImpl->checkTrustedRecursive()");
	
        return ArrayList.$new();
    };
});
