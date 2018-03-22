package org.apache.kerberos.dns;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Hashtable;
import java.util.Scanner;

import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

public class DnsLookup {

	Hashtable<String, Object> externalDnsEnv;
	Hashtable<String, Object> internalDnsEnv;
	public DnsLookup() {
		this.setDNSEnv();
	}

	public void setDNSEnv() {
		externalDnsEnv = new Hashtable<String, Object>();
		externalDnsEnv.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
		externalDnsEnv.put("java.naming.provider.url", "dns://external.dns.senia.org");
		internalDnsEnv = new Hashtable<String, Object>();
		internalDnsEnv.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
		internalDnsEnv.put("java.naming.provider.url", "dns://" + loadInternalDnsServer());
	}

	public String lookupExternalARecord(String aRecord) {
		DirContext ictx;
		try {
			ictx = new InitialDirContext(externalDnsEnv);
			Attributes attrs = ictx.getAttributes(aRecord, new String[] { "A" });
			return attrs.get("A").get().toString();
		} catch (NameNotFoundException e) {
			// TODO Auto-generated catch block
			return null;
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			return "_DNS_ERROR_";
		}

	}
	public String lookupInternalARecord(String aRecord)  {
		DirContext ictx;
		try {
			ictx = new InitialDirContext(internalDnsEnv);
			Attributes attrs = ictx.getAttributes(aRecord, new String[] { "A" });
			return attrs.get("A").get().toString();
		} catch (NameNotFoundException e) {
			// TODO Auto-generated catch block
			return null;
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			return "_DNS_ERROR_";
		}

	}	

	public String lookupExternalPTRRecord(String ptrRecord) {
		String[] bytes = ptrRecord.split("\\.");
        String reverseDns = bytes[3] + "." + bytes[2] + "." + bytes[1] + "." + bytes[0] + ".in-addr.arpa";
		DirContext ictx;
		try {
			ictx = new InitialDirContext(externalDnsEnv);
			Attributes attrs = ictx.getAttributes(reverseDns, new String[] { "PTR" });
			return attrs.get("PTR").get().toString();
		} catch (NameNotFoundException e) {
			// TODO Auto-generated catch block
			return null;
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			return "_DNS_ERROR_";
		}

	}
	
	public String lookupInternalPTRRecord(String ptrRecord)  {
		String[] bytes = ptrRecord.split("\\.");
        String reverseDns = bytes[3] + "." + bytes[2] + "." + bytes[1] + "." + bytes[0] + ".in-addr.arpa";
		DirContext ictx;
		try {
			ictx = new InitialDirContext(internalDnsEnv);
			Attributes attrs = ictx.getAttributes(reverseDns, new String[] { "PTR" });
			return attrs.get("PTR").get().toString();
		} catch (NameNotFoundException e) {
			// TODO Auto-generated catch block
			return null;
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			return "_DNS_ERROR_";
		}

	}	

	public static String loadInternalDnsServer() {
		String nameServer = null;
		File file = new File("/etc/resolv.conf");
		Scanner scanner;
		try {
			scanner = new Scanner(file);
			while (scanner.hasNextLine()) {
				String lineFromFile = scanner.nextLine();
				if (lineFromFile.contains("nameserver")) {
					nameServer = lineFromFile.split("nameserver ")[1];
					break;
				}
			}
			scanner.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return nameServer;
	}
}
