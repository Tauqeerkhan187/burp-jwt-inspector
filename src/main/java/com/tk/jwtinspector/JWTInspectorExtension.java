package com.tk.jwtinspector;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

public class JWTInspectorExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api){
        api.extension().setName("JWT Inspector");

        Logging logging = api.logging();
        logging.logToOutput("JWT Inspector loaded successfully.");
        logging.logToOutput("Version: 0.1.0 (Phase 1 skeleton");
    }
}
