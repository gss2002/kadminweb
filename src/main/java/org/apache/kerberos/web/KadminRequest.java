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
import org.json.JSONObject;

/**
 * Servlet implementation class KadminRequest
 */
@WebServlet("/KadminRequest")
public class KadminRequest extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String keytabOutputPath = "";
	private static String kadminKeytab = "";
	private static String kadminPrincipal = "";
	private static String ticketCache = "";
	private static String realm = "";

       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public KadminRequest() {
        super();
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
		System.setProperty("sun.net.spi.nameservice.nameservers", "192.168.1.1");
		System.setProperty("sun.net.spi.nameservice.provider.1", "dns,sun");
		Kinit kinit = new Kinit(kadminPrincipal, ticketCache, kadminKeytab);
		Thread kinitThread = new Thread(kinit);
		kinitThread.setDaemon(true);
		kinitThread.start();
		System.out.println("Kinit Thread Started");
		
	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		String remote_host = request.getRemoteHost();
		 InetAddress addr = InetAddress.getByName(remote_host);
		 String remote_host_clean = addr.getHostName();
		String request_host = request.getParameter("host");
		System.out.println("remoteHost: "+remote_host_clean);
		System.out.println("requestHost: "+request_host);
		if (remote_host_clean.equalsIgnoreCase(request_host)) {
			KAdmin kadmin = new KAdmin();
			String principalIn = "host/"+remote_host_clean+"@"+realm;
			String keytabFileName = keytabOutputPath+"/"+remote_host_clean+".keytab";
			try {
				boolean createPrincipalSuccess = false;
				boolean createKeyTabSuccess = false;
				boolean doesPrincipalExist = false;
				doesPrincipalExist = kadmin.getPrincipal(principalIn, ticketCache);
				if (!(doesPrincipalExist)) {
					System.out.println(remote_host_clean+ " Principal Doesn't exist");
					createPrincipalSuccess = kadmin.createPrincipal(principalIn, ticketCache);
					if (!(createPrincipalSuccess)) {
						System.out.println(remote_host_clean+ " Creating Keytab");
						createKeyTabSuccess = kadmin.createKeyTab(principalIn, ticketCache, keytabOutputPath);
						System.out.println(remote_host_clean+ " KeyTab Creation Success: "+createKeyTabSuccess);

					}
	
				} else {
					System.out.println(remote_host_clean+ " Principal Exists: "+doesPrincipalExist);
					createKeyTabSuccess = kadmin.createKeyTab(principalIn, ticketCache, keytabOutputPath);
					System.out.println(remote_host_clean+ " KeyTab Creation Success: "+createKeyTabSuccess);
				}
				System.out.println(remote_host_clean+ " KeyTab Creation Success Status: "+createKeyTabSuccess);
				if (createKeyTabSuccess) {
					System.out.println(remote_host_clean+ " Exporting Keytab to JSON");
					ByteArrayOutputStream ba = this.loadKeytab(keytabFileName);
					String keytabBase64String = org.apache.commons.codec.binary.StringUtils.newStringUtf8(org.apache.
						commons.codec.binary.Base64.encodeBase64(ba.toByteArray()));
					JSONObject obj = new JSONObject(); 
					obj.put("host", remote_host_clean); 
					obj.put("keytab",keytabBase64String); 
					response.setContentType("application/json"); 
					response.getWriter().write(obj.toString()); 
				} else {
					System.out.println(remote_host_clean+ " No Keytab to JSON");
					response.sendError(204);
				}
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				response.sendError(400);
				e.printStackTrace();
			}
		} else {
			response.sendError(403);
		}
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
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
	
	private ByteArrayOutputStream loadKeytab(String fileName)	{
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
				bos.write(buf, 0, readNum); //no doubt here is 0
			}
		} catch (IOException ex) {
			ex.printStackTrace();
		}
		return bos;
	}

}
