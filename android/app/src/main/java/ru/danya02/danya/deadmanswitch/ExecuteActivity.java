package ru.danya02.danya.deadmanswitch;

import android.content.Context;
import android.os.AsyncTask;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.TextView;

import java.io.IOException;
import java.io.InputStream;
import java.lang.ref.WeakReference;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;

public class ExecuteActivity extends AppCompatActivity {

    private TextView textView;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_execute);
        doConnect();
    }
    void doConnect(){
        RSANegotiator r = new RSANegotiator(this);
        r.execute();

    }

    static private class RSANegotiator extends AsyncTask<Void, String, Void> {

        class Challenge{
            public byte[] encryptedChallenge;
            public byte[] decryptedNonce;
            public byte[] decryptedDigest;
            public byte[] encryptedDigest;
            public String ipAddress;

            public void auth(){
                // TODO: implement.
            }

        }

        private WeakReference<ExecuteActivity> activityReference;

        RSANegotiator(ExecuteActivity context) {
            activityReference = new WeakReference<>(context);
        }

        @Override
        protected Void doInBackground(Void... voids) {
            Challenge ch = new Challenge();
            ch.auth();
            return null;
        }
        protected void onProgressUpdate(String... strings){
            ExecuteActivity activity = activityReference.get();
            if (activity == null || activity.isFinishing()) return;

            TextView textView = activity.findViewById(R.id.text_status);
            textView.setText(strings[0]);
        }
    }
}
