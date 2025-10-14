package com.techStack.authSys.config;

import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.LowLevelHttpRequest;
import com.google.api.client.http.LowLevelHttpResponse;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class NettyTransport extends HttpTransport {
    private final HttpClient httpClient;

    public NettyTransport(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    protected LowLevelHttpRequest buildRequest(String method, String url) throws IOException {
        return new NettyLowLevelHttpRequest(httpClient, method, url);
    }

    static class NettyLowLevelHttpRequest extends LowLevelHttpRequest {
        private final HttpClient httpClient;
        private final String method;
        private final String url;

        NettyLowLevelHttpRequest(HttpClient httpClient, String method, String url) {
            this.httpClient = httpClient;
            this.method = method;
            this.url = url;
        }

        @Override
        public void addHeader(String s, String s1) throws IOException {

        }
        @Override
        public LowLevelHttpResponse execute() throws IOException {
            try {
                return httpClient
                        .request(io.netty.handler.codec.http.HttpMethod.valueOf(method))
                        .uri(url)
                        .responseSingle((response, body) ->
                                body.asInputStream()
                                        .map(inputStream -> new NettyLowLevelHttpResponse(response, inputStream))
                        )
                        .block(); // 👈 Blocking is necessary here
            } catch (Exception e) {
                throw new IOException("Failed to execute request", e);
            }
        }


    }

    static class NettyLowLevelHttpResponse extends LowLevelHttpResponse {
        private final reactor.netty.http.client.HttpClientResponse response;
        private final java.io.InputStream content;

        NettyLowLevelHttpResponse(reactor.netty.http.client.HttpClientResponse response,
                                  java.io.InputStream content) {
            this.response = response;
            this.content = content;
        }

        @Override
        public int getStatusCode() {
            return response.status().code();
        }

        @Override
        public String getReasonPhrase() throws IOException {
            return "";
        }

        @Override
        public InputStream getContent() {
            return content;
        }

        @Override
        public String getContentEncoding() {
            return response.responseHeaders().get("Content-Encoding");
        }

        @Override
        public long getContentLength() {
            String length = response.responseHeaders().get("Content-Length");
            return length == null ? -1 : Long.parseLong(length);
        }

        @Override
        public String getContentType() {
            return response.responseHeaders().get("Content-Type");
        }

        @Override
        public String getStatusLine() {
            return response.status().toString();
        }

        @Override
        public int getHeaderCount() {
            return response.responseHeaders().size();
        }

        @Override
        public String getHeaderName(int index) {
            List<String> names = new ArrayList<>(response.responseHeaders().names());
            return names.get(index);
        }

        @Override
        public String getHeaderValue(int index) {
            List<String> names = new ArrayList<>(response.responseHeaders().names());
            String name = names.get(index);
            return response.responseHeaders().get(name);
        }

    }
}
