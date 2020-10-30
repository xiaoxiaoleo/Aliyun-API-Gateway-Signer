/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package com.alibaba.cloudapi.client;

import com.alibaba.cloudapi.client.constant.Constants;
import com.alibaba.cloudapi.client.constant.HttpHeader;
import com.alibaba.cloudapi.client.constant.SystemHeader;
import javax.crypto.spec.SecretKeySpec;

import javax.crypto.Mac;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.TreeMap;

/**
 * Created by fred on 16/9/7.
 */
public class SignUtil {

    /**
     */
    public static String sign(String appSecret, String[] signHeaders, String method , Map<String, String> headersParams , String pathWithParameter , Map<String, String> queryParams , Map<String, String> formParam) {
        try {
            Mac hmacSha256 = Mac.getInstance(Constants.CLOUDAPI_HMAC);
            byte[] keyBytes = appSecret.getBytes(Constants.CLOUDAPI_ENCODING);
            hmacSha256.init(new SecretKeySpec(keyBytes, 0, keyBytes.length, Constants.CLOUDAPI_HMAC));

            //
            String signString = buildStringToSign(signHeaders, method , headersParams , pathWithParameter , queryParams , formParam);

            System.out.println("------------------");
            System.out.println(signString);
            System.out.println("------------------");

            //
            byte[] signResult = hmacSha256.doFinal(signString.getBytes(Constants.CLOUDAPI_ENCODING));
            byte[] base64Bytes = Base64.getEncoder().encode(signResult);
            return new String(base64Bytes , Constants.CLOUDAPI_ENCODING);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     */
    private static String buildStringToSign(String[] signHeaders, String method , Map<String, String> headerParams, String pathWithParameter, Map<String, String> queryParams ,  Map<String, String> formParams) {

        StringBuilder sb = new StringBuilder();
        sb.append(method).append(Constants.CLOUDAPI_LF);

        //
        for( String key : headerParams.keySet()){
            if(key.toLowerCase().equals(HttpHeader.CLOUDAPI_HTTP_HEADER_ACCEPT)){
                sb.append(headerParams.get(key));
            }
        }
        sb.append(Constants.CLOUDAPI_LF);

        //
        for( String key : headerParams.keySet()){
            if(key.toLowerCase().equals(HttpHeader.CLOUDAPI_HTTP_HEADER_CONTENT_MD5)){
                sb.append(headerParams.get(key));
            }
        }
        sb.append(Constants.CLOUDAPI_LF);

        //

        for( String key : headerParams.keySet()){
            if(key.toLowerCase().equals(HttpHeader.CLOUDAPI_HTTP_HEADER_CONTENT_TYPE)){
                sb.append(headerParams.get(key));
            }
        }
        sb.append(Constants.CLOUDAPI_LF);


        //
        if (headerParams.get(HttpHeader.CLOUDAPI_HTTP_HEADER_DATE) != null) {
            sb.append(headerParams.get(HttpHeader.CLOUDAPI_HTTP_HEADER_DATE));
        }
        sb.append(Constants.CLOUDAPI_LF);

        //
        sb.append(buildHeaders(signHeaders, headerParams));

        //
        sb.append(buildResource(pathWithParameter, queryParams , formParams));
        return sb.toString();
    }

    /**
     */
    private static String buildResource(String pathWithParameter, Map<String, String> queryParams ,  Map<String, String> formParams) {
        StringBuilder result = new StringBuilder();
        result.append(pathWithParameter);

        //
        TreeMap<String , String> parameter = new TreeMap<>();
        if(null!= queryParams && queryParams.size() > 0){
            parameter.putAll(queryParams);
        }

        if(null != formParams && formParams.size() > 0){
            parameter.putAll(formParams);
        }

        if(parameter.size() > 0) {
            result.append("?");
            boolean isFirst = true;
            for (String key : parameter.keySet()) {
                if (isFirst == false) {
                    result.append("&");
                } else {
                    isFirst = false;
                }
                result.append(key).append("=").append(parameter.get(key));
            }
        }
        return result.toString();
    }

    /**
     *
     */
    private static String buildHeaders(String[] signHeaders, Map<String, String> headers) {
        //
        Map<String, String> headersToSign = new TreeMap<String, String>();

        if (headers != null) {
            StringBuilder signHeadersStringBuilder = new StringBuilder();

            int flag = 0;
            for (Map.Entry<String, String> header : headers.entrySet()) {
                if (Arrays.asList(signHeaders).contains(header.getKey())) {
                    if (flag != 0) {
                        signHeadersStringBuilder.append(",");
                    }
                    flag++;
                    signHeadersStringBuilder.append(header.getKey());
                    headersToSign.put(header.getKey(), header.getValue());
                }
            }

            //
            headers.put(SystemHeader.CLOUDAPI_X_CA_SIGNATURE_HEADERS, signHeadersStringBuilder.toString());
        }

        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : headersToSign.entrySet()) {
            sb.append(e.getKey()).append(':').append(e.getValue()).append(Constants.CLOUDAPI_LF);
        }
        return sb.toString();
    }

}
