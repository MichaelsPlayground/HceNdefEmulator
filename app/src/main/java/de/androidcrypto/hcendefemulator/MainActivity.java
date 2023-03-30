package de.androidcrypto.hcendefemulator;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import java.util.Calendar;
import java.util.Date;
import java.util.Timer;
import java.util.TimerTask;

public class MainActivity extends AppCompatActivity {

    private final String TAG = "HceNdefEmulator";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        PackageManager pm = this.getPackageManager();

        if (!pm.hasSystemFeature(PackageManager.FEATURE_NFC_HOST_CARD_EMULATION)) {
            Log.i(TAG, "Missing HCE functionality.");
        }

        Context context = this;
        Timer t = new Timer();

        TimerTask task = new TimerTask() {
            @Override
            public void run() {
                Date dt = Calendar.getInstance().getTime();
                Log.d(TAG, "Set time as " + dt.toString());
                TextView t = findViewById(R.id.current_time);
                if (t != null) {
                    runOnUiThread(new Runnable() {
                        public void run() {
                            t.setText(dt.toString());
                        }
                    });
                }
                String characters66 = "";
                for (int i = 0; i < 466; i++) {
                    characters66 = characters66 + "A";
                }
                String test = Utils.getTimestamp() + " on " + characters66;
                if (pm.hasSystemFeature(PackageManager.FEATURE_NFC_HOST_CARD_EMULATION)) {
                    //Intent intent = new Intent(context, CardService.class);
                    Intent intent = new Intent(context, NdefHostApduServiceOwn.class);
                    intent.putExtra("ndefMessage", dt.toString());
                    //intent.putExtra("ndefMessage", test);
                    // Log.d(TAG, intent.toString());
                    startService(intent);
                }
            }

        };
        //t.scheduleAtFixedRate(task, 0, 1000); // every second
        t.scheduleAtFixedRate(task, 0, 60000); // every minute
    }
}