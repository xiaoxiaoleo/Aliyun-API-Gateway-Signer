
package com.alibaba.cloudapi.client;


import com.alibaba.cloudapi.client.constant.Constants;
import com.alibaba.cloudapi.client.constant.HttpHeader;
import com.alibaba.cloudapi.client.constant.HttpMethod;
import com.alibaba.cloudapi.client.constant.ContentType;
import com.alibaba.cloudapi.client.constant.SystemHeader;
import okhttp3.MediaType;
import okhttp3.RequestBody;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.*;



public class HttpUtil {


    public static List<String> httpGet(String appKey, String appSecret, String[] signHeaders, String host, String path , Map<String , String> queryParams , Map<String , String> headerParams)
    {

        List<String> request = buildHttpRequest(appKey, appSecret , signHeaders, HttpMethod.CLOUDAPI_GET, host , path , null , queryParams , null  , null , ContentType.CLOUDAPI_CONTENT_TYPE_FORM , ContentType.CLOUDAPI_CONTENT_TYPE_JSON , headerParams);
        return request;
    }
    public static List<String> httpPostForm(String appKey, String appSecret, String[] signHeaders, String host, String path , Map<String , String> queryParams , Map<String , String> formParams , Map<String , String> headerParams)
    {
        List<String> request = buildHttpRequest(appKey, appSecret ,signHeaders,  HttpMethod.CLOUDAPI_POST , host , path , null , queryParams , formParams , null , ContentType.CLOUDAPI_CONTENT_TYPE_FORM , ContentType.CLOUDAPI_CONTENT_TYPE_JSON , headerParams);
        return request;
    }

    public  static List<String> httpPostBytes(String appKey, String appSecret, String[] signHeaders, String host, String path , Map<String , String> queryParams , byte[] body , Map<String , String> headerParams )
    {
        List<String> request = buildHttpRequest(appKey, appSecret , signHeaders, HttpMethod.CLOUDAPI_POST , host , path , null , queryParams , null  , body , ContentType.CLOUDAPI_CONTENT_TYPE_STREAM , ContentType.CLOUDAPI_CONTENT_TYPE_JSON , headerParams);
        return request;
    }

    private  static List<String> buildHttpRequest(String appKey, String appSecret, String[] signHeaders, String method , String host , String path , Map<String , String> pathParams , Map<String , String> queryParams ,  Map<String , String> formParams , byte[] body , String requestContentType , String acceptContentType , Map<String , String> headerParams){

        List<String> finalHeaders = new ArrayList<>();

        /**
         */
        String pathWithPathParameter = HttpUtil.combinePathParam(path , pathParams);


        if(null == headerParams){
            headerParams = new HashMap<String, String>();
        }


        Date current = new Date();
        //
        //headerParams.put(HttpHeader.CLOUDAPI_HTTP_HEADER_DATE , "Sun, 18 Oct 2020 16:42:59 GMT");

        for(String header : signHeaders){
            if(header.toLowerCase().contains(HttpHeader.CLOUDAPI_HTTP_HEADER_DATE)){
                //headerParams.put(header, HttpUtil.getHttpDateHeaderValue(current));
                headerParams.put(header, HttpUtil.getHttpDateHeaderValue(current));

            }

            if(header.toLowerCase().contains(SystemHeader.CLOUDAPI_X_CA_TIMESTAMP)){
                headerParams.put(header, String.valueOf(current.getTime()));
                //headerParams.put(SystemHeader.CLOUDAPI_X_CA_TIMESTAMP, String.valueOf("1603039241373"));
            }

            if(header.toLowerCase().contains(SystemHeader.CLOUDAPI_X_CA_KEY)){
                headerParams.put(header, appKey);
            }

            if(header.toLowerCase().contains(SystemHeader.CLOUDAPI_X_CA_NONCE)){
                headerParams.put(header, UUID.randomUUID().toString());
                //headerParams.put(header,String.valueOf("e75f094e-6ff0-4de4-9b52-acf6da868927"));
            }
            if(header.toLowerCase().contains(HttpHeader.CLOUDAPI_HTTP_HEADER_HOST)){
                headerParams.put(header, host);
            }

            if(header.toLowerCase().contains(SystemHeader.CLOUDAPI_X_CA_SIGNATURE_METHOD)){
                headerParams.put(header, Constants.CLOUDAPI_HMAC);
            }
        }


        //

        //headerParams.put(SystemHeader.CLOUDAPI_X_CA_NONCE, "22791fae-891d-489d-9597-cd881e987715");

        //
        //headerParams.put(HttpHeader.CLOUDAPI_HTTP_HEADER_USER_AGENT, Constants.CLOUDAPI_USER_AGENT);

        //

        //
/*        headerParams.put(SystemHeader.CLOUDAPI_X_CA_KEY, appKey);
        //
        headerParams.put(SystemHeader.CLOUDAPI_X_CA_VERSION , Constants.CLOUDAPI_CA_VERSION_VALUE);*/

        //

        //headerParams.put(HttpHeader.CLOUDAPI_HTTP_HEADER_CONTENT_TYPE , requestContentType);

        //
        //headerParams.put(HttpHeader.CLOUDAPI_HTTP_HEADER_ACCEPT , acceptContentType);
/*
        headerParams.put(SystemHeader.CLOUDAPI_X_CA_SIGNATURE_METHOD, Constants.CLOUDAPI_HMAC);*/

        /**
         */
        RequestBody requestBody = null;
        if(null != formParams && formParams.size() > 0){
            requestBody = RequestBody.create(MediaType.parse(requestContentType) , buildParamString(formParams));
        }
        /**
         */
        else if(null != body && body.length >0){
            requestBody = RequestBody.create(MediaType.parse(requestContentType) , body);
            headerParams.put(HttpHeader.CLOUDAPI_HTTP_HEADER_CONTENT_MD5 , HttpUtil.base64AndMD5(body));
        }

        /**
         */
        headerParams.put(SystemHeader.CLOUDAPI_X_CA_SIGNATURE, SignUtil.sign(appSecret, signHeaders, method , headerParams , pathWithPathParameter , queryParams , formParams));

        /**
         */
        for(String key : headerParams.keySet()){
            String value = headerParams.get(key);
            if(null != value && value.length() > 0){
                byte[] temp = value.getBytes(Constants.CLOUDAPI_ENCODING);
                headerParams.put(key , new String(temp , Constants.CLOUDAPI_HEADER_ENCODING));
            }
        }




/*        for (String keys : headerParams.keySet())
        {
            System.out.println(keys + ":"+ headerParams.get(keys));
        }

        */
        for (Map.Entry<String, String> entry : headerParams.entrySet()) {
            finalHeaders.add(String.format("%s: %s", entry.getKey(), entry.getValue()));
        }

        //Headers headers = Headers.of(headerParams);
        finalHeaders.sort(String.CASE_INSENSITIVE_ORDER);
        return finalHeaders;
    }

    public static String buildParamString(Map<String , String> params){
        StringBuilder result = new StringBuilder();
        if(null != params && params.size() > 0){
            boolean isFirst = true;
            for(String key : params.keySet()){
                if(isFirst){
                    isFirst = false;
                }
                else{
                    result.append("&");
                }

                try {
                    result.append(key).append("=").append(URLEncoder.encode(params.get(key), Constants.CLOUDAPI_ENCODING.displayName()));
                }
                catch (UnsupportedEncodingException ex){
                    throw new RuntimeException(ex);
                }

            }
        }

        return result.toString();
    }

    public static String combinePathParam(String path , Map<String , String> pathParams){
        if(pathParams == null){
            return path;
        }

        for(String key : pathParams.keySet()){
            path = path.replace("["+key+"]" , pathParams.get(key));
        }
        return path;
    }



    public static String getHttpDateHeaderValue(Date date) {
        SimpleDateFormat dateFormat = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss z", Locale.US);
        dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
        return dateFormat.format(date);
    }

    /**
     *
     * @return
     */
    public static String base64AndMD5(byte[] bytes) {
        if (bytes == null) {
            throw new IllegalArgumentException("bytes can not be null");
        }
        try {
            final MessageDigest md = MessageDigest.getInstance("MD5");
            md.reset();
            md.update(bytes);
            final byte[] encodeBytes = Base64.getEncoder().encode(md.digest());
            //final byte[] encodeBytes = Base64.encode(md.digest() , Base64.DEFAULT);
            byte[] encodeBytes2 = new byte[24];
            for(int i = 0 ; i < 24 ; i++){
                encodeBytes2[i] = encodeBytes[i];
            }
            return new String(encodeBytes2 , Constants.CLOUDAPI_ENCODING);
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("unknown algorithm MD5");
        }
    }

}