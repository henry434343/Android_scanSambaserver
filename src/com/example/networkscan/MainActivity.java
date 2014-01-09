package com.example.networkscan;


import java.util.ArrayList;

import com.example.networkscan.NetWorkScanner.serverBean;

import android.os.Bundle;
import android.app.Activity;
import android.view.Menu;

public class MainActivity extends Activity {
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		
		NetWorkScanner scanner = new NetWorkScanner();
		scanner.setListener(new NetWorkScanner.ScanListener() {
			
			@Override
			public void onFinish(ArrayList<serverBean> servers) {
				// TODO Auto-generated method stub
				
			}
		});
		scanner.start();

		
	}  
	
	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.main, menu);
		return true;
	}

}
