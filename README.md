Android_scanSambaserver
=======================
for test purpose

		NetWorkScanner scanner = new NetWorkScanner();
		scanner.setListener(new NetWorkScanner.ScanListener() {
			
			@Override
			public void onFinish(ArrayList<serverBean> servers) {
				// TODO Auto-generated method stub
				for (serverBean bean : servers) {
					Log.i("chauster", bean.serverName);
					Log.i("chauster", bean.serverIp);
				}
			}
		});
		scanner.start();
