package com.code19.andpgp.fragment;

import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.v4.app.Fragment;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import com.code19.andpgp.R;
import com.code19.andpgp.X;

/**
 * Created by gh0st on 2016/9/27.
 */

public class StringFragment extends Fragment implements View.OnClickListener {

    private EditText mEtinput;
    private TextView mTvdecoderesult;
    private TextView mTvencoderesult;
    private TextView mTvkeypair;
    private String mEncodeingstr;
    private String mDecoingstr;

    @Nullable
    @Override
    public View onCreateView(LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_string, null);
        mEtinput = (EditText) view.findViewById(R.id.et_input);
        mTvkeypair = (TextView) view.findViewById(R.id.tv_key_pair);
        mTvdecoderesult = (TextView) view.findViewById(R.id.tv_decode_result);
        mTvencoderesult = (TextView) view.findViewById(R.id.tv_encode_result);
        Button btnencode = (Button) view.findViewById(R.id.btn_encode);
        Button btndecode = (Button) view.findViewById(R.id.btn_decode);
        Button btngeneratersakey = (Button) view.findViewById(R.id.btn_generate_rsa_key);
        btnencode.setOnClickListener(this);
        btndecode.setOnClickListener(this);
        btngeneratersakey.setOnClickListener(this);
        X.init();
        return view;
    }

    @Override
    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.btn_encode:
                String inputString = mEtinput.getText().toString();
                mEncodeingstr = X.pu_en(inputString);
                mTvencoderesult.setText(mEncodeingstr);
                break;
            case R.id.btn_decode:
                if (!TextUtils.isEmpty(mEncodeingstr)) {
                    mDecoingstr = X.pr_de(mEncodeingstr);
                    mTvdecoderesult.setText(mDecoingstr);
                }
                break;
            case R.id.btn_generate_rsa_key:
                break;
        }
    }
}
