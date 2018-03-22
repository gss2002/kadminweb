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
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.kerberos.web;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetAddress;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.kerberos.KAdmin;
import org.apache.kerberos.Kinit;
import org.apache.kerberos.dns.DnsLookup;
import org.apache.log4j.Logger;
import org.json.JSONObject;


/**
 * Servlet implementation class KadminRequest
 */
@WebServlet("/KadminRequest")
public class KadminRequest extends HttpServlet {
	Logger LOG = Logger.getLogger(KadminRequest.class);
	private static final long serialVersionUID = 1L;
	private static String keytabOutputPath = "";
	private static String kadminKeytab = "";
	private static String kadminPrincipal = "";
	private static String ticketCache = "";
	private static String realm = "";
	private static final String kadmin_apikey = "z1s7QtCcUu567CEZi3wI5gFhcSlatv";
	private DnsLookup dnsLookup;

	/**
	 * @see HttpServlet#HttpServlet()
	 */
	public KadminRequest() {
		super();
		dnsLookup = new DnsLookup();
	}

	/**
	 * @see Servlet#init(ServletConfig)
	 */
	public void init(ServletConfig config) throws ServletException {
		// TODO Auto-generated method stub
		realm = System.getProperty("realm");
		keytabOutputPath = System.getProperty("keytabOutputPath");
		kadminPrincipal = System.getProperty("kadminPrincipal");
		kadminKeytab = System.getProperty("kadminKeytab");
		ticketCache = System.getProperty("ticketCache");
		Kinit kinit = new Kinit(kadminPrincipal, ticketCache, kadminKeytab);
		Thread kinitThread = new Thread(kinit);
		kinitThread.setDaemon(true);
		kinitThread.start();
		LOG.info("Kinit Thread Started");

	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		// TODO Auto-generated method stub
		String request_host = "";
		String svcHost = "";
		String krbSvcName = "";
		String krbUserName = "";
		boolean isHostKeytab = true;
		boolean isKrbService = false;
		boolean isKrbHeadless = false;
		boolean isNotValid = false;
		boolean isKeyDistOwner = true;
		String remote_addr = request.getRemoteAddr();
		String remoteHostDNS = dnsLookup.lookupExternalPTRRecord(remote_addr);
		if (remoteHostDNS != null) {
			if (remoteHostDNS.endsWith(".")) {
				remoteHostDNS = remoteHostDNS.substring(0, remoteHostDNS.length()-1);
			}
		}
		if (remoteHostDNS == null) {
			remoteHostDNS = dnsLookup.lookupInternalPTRRecord(remote_addr);
			if (remoteHostDNS != null) {
				if (remoteHostDNS.endsWith(".")) {
					remoteHostDNS = remoteHostDNS.substring(0, remoteHostDNS.length()-1);
				}
			} 
		}
		if (remoteHostDNS.equalsIgnoreCase("_DNS_ERROR_")) {
			remoteHostDNS = "";
		}
		String remote_host_clean = remoteHostDNS;


		if (request.getParameter("service") != null && request.getParameter("svchost") != null) {
			isKrbService = true;
			isHostKeytab = false;
		}
		if (request.getParameter("headless") != null) {
			isKrbHeadless = true;
			isHostKeytab = false;
		}

		if (request.getParameter("host") != null) {
			request_host = request.getParameter("host").trim();
		}

		if (isKrbService) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Requesting KRBService Principal");
			}
			request_host = request.getParameter("host").trim();
			svcHost = request.getParameter("svchost").trim();
			krbSvcName = request.getParameter("service").trim();
		}
		if (isKrbHeadless) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Requesting KRB Headless Principal");
			}
			krbUserName = request.getParameter("headless").trim();
		}

		if (LOG.isDebugEnabled()) {
			LOG.debug("remoteHost: " + remote_host_clean);
			LOG.debug("requestHost: " + request_host);
			LOG.debug("svcHost: " + svcHost);
			LOG.debug("krbServiceName: " + krbSvcName);
			LOG.debug("krbUserName: " + krbUserName);

		}
		String api_string_in = "";
		if (request.getParameter("apikey") != null) {
			api_string_in = request.getParameter("apikey").trim();
		}
		if (kadmin_apikey.equalsIgnoreCase(api_string_in)) {

			KAdmin kadmin = new KAdmin();
			String principalIn = "";
			String keytabFileName = "";
			if (isKrbService) {
				LOG.debug("svcPrincipal: " + isKrbService);
				if (remote_host_clean.equalsIgnoreCase(request_host)) {
					principalIn = krbSvcName + "/" + svcHost + "@" + realm;
					keytabFileName = keytabOutputPath + "/" + krbSvcName + "-" + svcHost + ".keytab";
					isNotValid = false;
				} else {
					isNotValid = true;
				}
				LOG.debug("svcPrincipal isNotValid: " + isNotValid);
			} else if (isHostKeytab) {
				LOG.debug("isHostKeytab: " + isHostKeytab);
				if (remote_host_clean.equalsIgnoreCase(request_host)) {
					principalIn = "host/" + remote_host_clean + "@" + realm;
					keytabFileName = keytabOutputPath + "/" + remote_host_clean + ".keytab";
				} else {
					isNotValid = true;
				}
				LOG.debug("isHostKeytab isNotValid: " + isNotValid);
			} else if (isKrbHeadless) {
				LOG.debug("isKrbHeadless: " + isKrbHeadless);

				if (krbUserName.startsWith("hdfs")) {
					isNotValid = true;
				}
				if (krbUserName.startsWith("yarn")) {
					isNotValid = true;
				}
				if (krbUserName.startsWith("hive")) {
					isNotValid = true;
				}
				if (krbUserName.startsWith("hbase")) {
					isNotValid = true;
				}
				if (krbUserName.startsWith("ambari-qa")) {
					isNotValid = true;
				}
				if (krbUserName.startsWith("mapred")) {
					isNotValid = true;
				}
				if (krbUserName.startsWith("keyadmin")) {
					isNotValid = true;
				}
				if (krbUserName.startsWith("rangeradmin")) {
					isNotValid = true;
				}
				if (krbUserName.startsWith("spark")) {
					isNotValid = true;
				}
				if (krbUserName.startsWith("keydist")) {
					isNotValid = true;
				}
				if (krbUserName.contains("krbtgt")) {
					isNotValid = true;
				}
				if (krbUserName.contains("kadmin")) {
					isNotValid = true;
				}
				if (krbUserName.contains("K/M")) {
					isNotValid = true;
				}
				if (krbUserName.contains("kiprop")) {
					isNotValid = true;
				}
				if (krbUserName.contains("/admin")) {
					isNotValid = true;
				}
				if (remote_host_clean.equalsIgnoreCase(request_host)) {
					principalIn = krbUserName + "@" + realm;
					keytabFileName = keytabOutputPath + "/" + krbUserName + ".headless.keytab";
					isNotValid = false;				
				}
				LOG.debug("headlessKeytab isNotValid: " + isNotValid);
			} else {
				isNotValid = true;
			}
			LOG.debug("global isNotValid: " + isNotValid);
			LOG.debug("global keytabFileName: " + keytabFileName);
			LOG.debug("global principalIn: " + principalIn);

			if (!(isNotValid)) {
				try {
					boolean createPrincipalSuccess = false;
					boolean createKeyTabSuccess = false;
					boolean doesPrincipalExist = false;
					doesPrincipalExist = kadmin.getPrincipal(principalIn, ticketCache);
					isKeyDistOwner = kadmin.checkPrincipalOwner(principalIn, ticketCache);
					LOG.debug("global doesPrincipalExist: " + doesPrincipalExist);
					LOG.debug("global isHostKeytab: " + isHostKeytab);

					LOG.debug("global isKeyDistOwner: " + isKeyDistOwner);


					if (!(doesPrincipalExist)) {
						if (LOG.isDebugEnabled()) {
							LOG.debug(remote_host_clean + " Principal Doesn't exist");
						}
						createPrincipalSuccess = kadmin.createPrincipal(principalIn, ticketCache);
						if (!(createPrincipalSuccess)) {
							if (LOG.isDebugEnabled()) {
								LOG.debug(remote_host_clean + " Creating Keytab");
							}
							createKeyTabSuccess = kadmin.createKeyTab(principalIn, ticketCache, keytabOutputPath);
							if (LOG.isDebugEnabled()) {
								LOG.debug(remote_host_clean + " KeyTab Creation Success: " + createKeyTabSuccess);
							}
						}

					} else {
						if (LOG.isDebugEnabled()) {
							LOG.debug(remote_host_clean + " Principal Exists: " + doesPrincipalExist);
						}
						if (isKeyDistOwner || isHostKeytab) {
							createKeyTabSuccess = kadmin.createKeyTab(principalIn, ticketCache, keytabOutputPath);
							if (LOG.isDebugEnabled()) {
								LOG.debug(remote_host_clean + " KeyTab Creation Success: " + createKeyTabSuccess);
							}
						}
					}
					if (LOG.isDebugEnabled()) {
						LOG.debug(remote_host_clean + " KeyTab Creation Success Status: " + createKeyTabSuccess);
					}
					if (createKeyTabSuccess) {
						if (LOG.isDebugEnabled()) {
							LOG.debug(remote_host_clean + " Exporting Keytab to JSON");
						}
						ByteArrayOutputStream ba = this.loadKeytab(keytabFileName);
						String keytabBase64String = org.apache.commons.codec.binary.StringUtils
								.newStringUtf8(org.apache.commons.codec.binary.Base64.encodeBase64(ba.toByteArray()));
						JSONObject obj = new JSONObject();
						obj.put("host", remote_host_clean);
						obj.put("keytab", keytabBase64String);
						response.setContentType("application/json");
						response.getWriter().write(obj.toString());
					} else {
						if (LOG.isDebugEnabled()) {
							LOG.debug(remote_host_clean + " No Keytab to JSON");
						}
						response.sendError(204);
					}
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					response.sendError(400);
					LOG.debug(e.toString());
				}
			} else {
				response.sendError(403);
			}
		} else {
			response.sendError(403);
		}
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		// TODO Auto-generated method stub
		doGet(request, response);
	}

	public String getClientIpAddr(HttpServletRequest request) {
		String ip = request.getHeader("X-Forwarded-For");
		if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
			ip = request.getHeader("Proxy-Client-IP");
		}
		if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
			ip = request.getHeader("WL-Proxy-Client-IP");
		}
		if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
			ip = request.getHeader("HTTP_CLIENT_IP");
		}
		if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
			ip = request.getHeader("HTTP_X_FORWARDED_FOR");
		}
		if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
			ip = request.getRemoteAddr();
		}
		return ip;
	}

	private ByteArrayOutputStream loadKeytab(String fileName) {
		File file = new File(fileName);
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(file);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		ByteArrayOutputStream bos = new ByteArrayOutputStream();

		byte[] buf = new byte[1024];
		try {
			for (int readNum; (readNum = fis.read(buf)) != -1;) {
				bos.write(buf, 0, readNum); // no doubt here is 0
			}
		} catch (IOException ex) {
			ex.printStackTrace();
		}
		return bos;
	}

}
