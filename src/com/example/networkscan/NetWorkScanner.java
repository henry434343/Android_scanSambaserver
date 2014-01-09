package com.example.networkscan;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import android.R.array;
import android.util.Log;

public class NetWorkScanner {

	private long network_ip = 0;
    private long network_start = 0;
    private long network_end = 0;
    
    private int size;
    private int pt_move = 2; // 1=backward 2=forward
    
    private String NOMAC = "00:00:00:00:00:00";
    
    public int cidr = 24;
    private static final String CMD_IP = " -f inet addr show %s";
    private static final String PTN_IP1 = "\\s*inet [0-9\\.]+\\/([0-9]+) brd [0-9\\.]+ scope global %s$";
    private static final String PTN_IP2 = "\\s*inet [0-9\\.]+ peer [0-9\\.]+\\/([0-9]+) scope global %s$"; // FIXME: Merge with PTN_IP1
    private static final String PTN_IF = "^%s: ip [0-9\\.]+ mask ([0-9\\.]+) flags.*";
    public String intf = "eth0";
    private static final int BUF = 8 * 1024;
    
    
    public NetWorkScanner() {
    	servers = new ArrayList<NetWorkScanner.serverBean>();
    }
    public class serverBean {
    	public String serverName;
    	public String serverIp;
    }
    
    private ScanListener scanListener;
    public void setListener(ScanListener scanListener){
    	this.scanListener = scanListener;
    }
    public interface ScanListener {
    	void onFinish(ArrayList<serverBean> servers);
    }
    private ArrayList<serverBean> servers;
    public void start(){
		String ip = null;  
		try {
	        for (Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces(); en
	                .hasMoreElements();) {
	            NetworkInterface ni = en.nextElement();
	            if (getInterfaceFirstIp(ni) != null) {
	            	ip = getInterfaceFirstIp(ni);
	                break;
	            }
	        }
//	        Log.i("chauster", "ip = "+ip);
	        getCidr();
//	        Log.i("chauster", "cidr = "+cidr);
	        network_ip = getUnsignedLongFromIp(ip);
//	        Log.i("chauster", "network_ip = "+network_ip);
            int shift = (32 - cidr);
            if (cidr < 31) {
                network_start = (network_ip >> shift << shift) + 1;
                network_end = (network_start | ((1 << shift) - 1)) - 1;
            } else {
                network_start = (network_ip >> shift << shift);
                network_end = (network_start | ((1 << shift) - 1));
            }
//            Log.i("chauster", "network_start = "+network_start);
//            Log.i("chauster", "network_end = "+network_end);
		} catch (SocketException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
//			Log.i("chauster", "e = "+e.toString());
		}

		
		size = (int) (network_end - network_start + 1);
        Log.v("chauster", "start=" + getIpFromLongUnsigned(network_start) + " (" + network_start
                + "), end=" + getIpFromLongUnsigned(network_end) + " (" + network_end
                + "), length=" + size);
        
        
        scan();
    }
    
    private void scan(){
        if (network_ip <= network_end && network_ip >= network_start) {
            Log.i("chauster", "Back and forth scanning");
            launch(network_start);

            // hosts
            long pt_backward = network_ip;
            long pt_forward = network_ip + 1;
            long size_hosts = size - 1;

            for (int i = 0; i < size_hosts; i++) {
                // Set pointer if of limits
                if (pt_backward <= network_start) {
                    pt_move = 2;
                } else if (pt_forward > network_end) {
                    pt_move = 1;
                }   
                // Move back and forth
                if (pt_move == 1) {
                    launch(pt_backward);
                    pt_backward--;
                    pt_move = 2;
                } else if (pt_move == 2) {
                    launch(pt_forward);
                    pt_forward++;
                    pt_move = 1;
                }
            }
            scanListener.onFinish(servers);
            Log.i("chauster", "finish scan");
        } else {
            Log.i("chauster", "Sequencial scanning");
            for (long i = network_start; i <= network_end; i++) {
                launch(i);
            }
            Log.i("chauster", "finish scan");
            scanListener.onFinish(servers);
        }
	}
	
    private String getHardwareAddress(String ip) {
        String hw = NOMAC;
        try {
            if (ip != null) {
                String ptrn = String.format("^%s\\s+0x1\\s+0x2\\s+([:0-9a-fA-F]+)\\s+\\*\\s+\\w+$", ip.replace(".", "\\."));
                Pattern pattern = Pattern.compile(ptrn);
                BufferedReader bufferedReader = new BufferedReader(new FileReader("/proc/net/arp"), BUF);
                String line;
                Matcher matcher;
                while ((line = bufferedReader.readLine()) != null) {
                    matcher = pattern.matcher(line);
                    if (matcher.matches()) {
                        hw = matcher.group(1);
                        break;
                    }
                }
                bufferedReader.close();
            } else {
                Log.e("chauster", "ip is null");
            }
        } catch (IOException e) {
            Log.e("chauster", "Can't open/read file ARP: " + e.getMessage());
            return hw;
        }
        return hw;
    }
	
    private void launch(final long i){
        new Thread(new Runnable() {
			
			@Override
			public void run() {
				// TODO Auto-generated method stub
				String addr = getIpFromLongUnsigned(i);

	            // Create host object
	            String hardwareAddress = NOMAC;
	            try {
	                InetAddress h = InetAddress.getByName(addr);
	                // Arp Check #1
	                hardwareAddress = getHardwareAddress(addr);
	                if(!NOMAC.equals(hardwareAddress)){
//		                Log.i("chauster", "hardwareAddress ="+hardwareAddress);

	                    publish(addr);  
	                    return;
	                }  
	                // Native InetAddress check
	                if (h.isReachable(getRate())) {
//	                	Log.i("chauster", "h = "+h);
	                	publish(addr);
	                    return;
	                }
	                // Arp Check #2
	                hardwareAddress = getHardwareAddress(addr);
	                if(!NOMAC.equals(hardwareAddress)){
//		                Log.i("chauster", "hardwareAddress ="+hardwareAddress);

	                	publish(addr);
	                    return;
	                }
	                // Arp Check #3
	                hardwareAddress = getHardwareAddress(addr);
	                if(!NOMAC.equals(hardwareAddress)){
//		                Log.i("chauster", "hardwareAddress ="+hardwareAddress);

	                	publish(addr);
	                    return;
	                }

	            } catch (IOException e) {
	            } 
			}
		}).start();
	}
	
	private void publish(String ipAddress){
        try {
            String hostname = (InetAddress.getByName(ipAddress)).getCanonicalHostName();
//            Log.i("chauster", "ipAddress = "+ipAddress);
//            Log.i("chauster", "hostname = "+hostname);

            serverBean server = new serverBean();
            server.serverIp = ipAddress;
            server.serverName = hostname;
            checkSambe(server);
        } catch (UnknownHostException e) {
            Log.e("chauster", e.getMessage());
        }
	}
	
	
	private void checkSambe(final serverBean server){
		new Thread(new Runnable() {
			
			@Override
			public void run() {
				// TODO Auto-generated method stub
		        try  
		        {  
		         Socket ServerSok = new Socket(server.serverIp,445);  
		         Log.i("chauster", "Samba server : "+server.serverIp);
		         Log.i("chauster", "Samba serverName : "+server.serverName);
		         ServerSok.close();  
		         servers.add(server);
		        }  
		        catch (Exception e)  
		        {  
//		        	Log.i("chauster", "e = "+e.toString());
		            e.printStackTrace();   
		        } 
			}
		}).start();
	}
	private int getRate() {
		return 800;
	}
	
    private String getIpFromLongUnsigned(long ip_long) {
        String ip = "";
        for (int k = 3; k > -1; k--) {
            ip = ip + ((ip_long >> k * 8) & 0xFF) + ".";
        }
        return ip.substring(0, ip.length() - 1);
    }
    
	
    private long getUnsignedLongFromIp(String ip_addr) {
		String[] a = ip_addr.split("\\.");
	    return (Integer.parseInt(a[0]) * 16777216 + Integer.parseInt(a[1]) * 65536
	                + Integer.parseInt(a[2]) * 256 + Integer.parseInt(a[3]));
	}
	   
    private String getInterfaceFirstIp(NetworkInterface ni) {
        if (ni != null) {
            for (Enumeration<InetAddress> nis = ni.getInetAddresses(); nis.hasMoreElements();) {
                InetAddress ia = nis.nextElement();
                if (!ia.isLoopbackAddress()) {
                    if (ia instanceof Inet6Address) {
                        continue;
                    }
                    return ia.getHostAddress();
                }
            }
        }
        return null;
    }
    

    private void getCidr() {
    	String match;
        // Running ip tools
        try {
            if ((match = runCommand("/system/xbin/ip", String.format(CMD_IP, intf), String.format(PTN_IP1, intf))) != null) {
                cidr = Integer.parseInt(match);
                Log.i("chauster", "1");
                return;
            } else if ((match = runCommand("/system/xbin/ip", String.format(CMD_IP, intf), String.format(PTN_IP2, intf))) != null) {
                cidr = Integer.parseInt(match);
                Log.i("chauster", "2");
                return;
            } else if ((match = runCommand("/system/bin/ifconfig", " " + intf, String.format(PTN_IF, intf))) != null) {
                cidr = IpToCidr(match);
                Log.i("chauster", "3");
                return;
            } else {
                Log.i("chauster", "cannot find cidr, using default /24");
            }
        } catch (NumberFormatException e) {
            Log.i("chauster", e.getMessage()+ " -> cannot find cidr, using default /24");
        }
    }
    
    private int IpToCidr(String ip) {
        double sum = -2;
        String[] part = ip.split("\\.");
        for (String p : part) {
            sum += 256D - Double.parseDouble(p);
        }
        return 32 - (int) (Math.log(sum) / Math.log(2d));
    }
    
    private String runCommand(String path, String cmd, String ptn) {
        try {
            if (new File(path).exists() == true) {
                String line;
                Matcher matcher;
                Pattern ptrn = Pattern.compile(ptn);
                Process p = Runtime.getRuntime().exec(path + cmd);
                BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()), BUF);
                while ((line = r.readLine()) != null) {
                    matcher = ptrn.matcher(line);
                    if (matcher.matches()) {
                        return matcher.group(1);
                    }
                }
            }
        } catch (Exception e) {
            Log.e("chauster", "Can't use native command: " + e.getMessage());
            return null;
        }
        return null;
    }
}
