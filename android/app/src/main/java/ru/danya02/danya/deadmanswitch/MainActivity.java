package ru.danya02.danya.deadmanswitch;

import android.content.Intent;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        ((Button) findViewById(R.id.b_do_work)).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                goExecuteActivity();
            }
        });

    }

    void goExecuteActivity(){
        Intent i = new Intent(MainActivity.this, ExecuteActivity.class);
        startActivity(i);
    }
}
