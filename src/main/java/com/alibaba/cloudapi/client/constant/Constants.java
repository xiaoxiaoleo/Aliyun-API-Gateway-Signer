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
package com.alibaba.cloudapi.client.constant;

import java.nio.charset.Charset;

/**
 * Created by fred on 16/9/7.
 */
public class Constants {
    //
    public static final Charset CLOUDAPI_ENCODING = Charset.forName("UTF-8");

    //
    public static final Charset CLOUDAPI_HEADER_ENCODING = Charset.forName("ISO-8859-1");

    //UserAgent
    public static final String CLOUDAPI_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.75 Safari/537.";
    //
    public static final String CLOUDAPI_LF = "\n";

    //
    public static final String CLOUDAPI_CA_HEADER_TO_SIGN_PREFIX_SYSTEM = "x-ca-";
    //
    public static final String CLOUDAPI_CA_VERSION_VALUE = "1";

    public static final String CLOUDAPI_HMAC = "HmacSHA256";
}
