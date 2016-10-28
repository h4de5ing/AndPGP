package com.code19.andpgp;

import android.support.v4.app.Fragment;
import android.util.SparseArray;

import com.code19.andpgp.fragment.FileFragment;
import com.code19.andpgp.fragment.ImageFragment;
import com.code19.andpgp.fragment.SettingFragment;
import com.code19.andpgp.fragment.StringFragment;
import com.code19.andpgp.fragment.WidgetFragment;

/**
 * Created by gh0st on 2016/9/27.
 * FragmentFactory 工厂管理类
 */

public class FragmentFactory {
    private static SparseArray<Fragment> map = new SparseArray<>();

    public static Fragment getFragment(int position) {
        Fragment fragment = null;
        if (map.get(position, fragment) != null) {
            return map.get(position);
        }
        switch (position) {
            case 0:
                fragment = new StringFragment();
                break;
            case 1:
                fragment = new ImageFragment();
                break;
            case 2:
                fragment = new FileFragment();
                break;
            case 3:
                fragment = new WidgetFragment();
                break;
            case 4:
                fragment = new SettingFragment();
                break;
        }
        return fragment;
    }
}
