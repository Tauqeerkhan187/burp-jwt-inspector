package com.tk.jwtinspector.detection.analysis.jwks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.List;

/**
 * Author: TK
 * Date: 23-11-2026
 * Purpose: Downloads a server's JWKS through Burp and returns the PEM of the key
 * that signed the token. Tries each candidate URL in order.
 *
 * Blocking network calls: callers must run fetchPem() off the Swing EDT.
 */

public class JwksFetcher {

     /** The PEM and the URL it came from, or the reason nothing worked. */
    public record Result(String pem, String sourceUrl, String error) {
        public boolean ok() { return pem != null; }
    }

    private final MontoyaApi api;

    public JwksFetcher(MontoyaApi api) {
        this.api = api;
    }

    public Result fetchPem(List<String> urls, String kid) {
        StringBuilder tried = new StringBuilder();
        for (String url : urls) {
            try {
                HttpResponse response = api.http().sendRequest(HttpRequest.httpRequestFromUrl(url)).response();
                if (response == null) {
                    tried.append(url).append(" -> no response; ");
                    continue;

                }
                if (response.statusCode() != 200) {
                    tried.append(url).append(" -> HTTP ").append(response.statusCode()).append("; ");
                    continue;

                }
                String pem = JwksKeys.toPem(JwksKeys.selectKey(response.bodyToString(), kid));
                return new Result(pem, url, null);
            }
            catch(Exception e){
                tried.append(url).append(" -> ").append(e.getMessage()).append("; ");
            }
        }
        return new Result(null, null, "No usable JWKS found. Tried: " + tried);

    }
}
