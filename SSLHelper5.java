package com.ztjw.smartgas.net;

import android.content.Context;

import com.ztjw.smartgas.R;
import com.ztjw.smartgas.utils.AppLogger;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * User:Created by andy on 2019/6/18.
 * Email:napoleno_1987@163.com
 * Description:单向认证，自己构建x509TrustManager对象
 */
public class SSLHelper5 {
    private Context context;

    public SSLHelper5(Context context) {
        this.context = context;
    }

    public SSLSocketFactory provideSSLSocketFactory() {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, provideTrustManagerArray(), new SecureRandom());
            return sslContext.getSocketFactory();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        }
        return null;
    }

    public X509TrustManager provideX509TrustManager() {
        return tm;
    }

    private TrustManager[] provideTrustManagerArray() {
        TrustManager[] trustManagers = new TrustManager[1];
        trustManagers[0] = tm;
        return trustManagers;
    }

    private X509TrustManager tm = new X509TrustManager() {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {

        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            try {
//                1. 获取客户端预埋的服务器端的证书对象
                InputStream mCaInputStream = context.
                        getResources().openRawResource(R.raw.server_cert);

//                2.生成符合x509标准的证书
                CertificateFactory mCertificateFactory = CertificateFactory.getInstance("X.509");
                X509Certificate certificate =
                        (X509Certificate) mCertificateFactory.generateCertificate(mCaInputStream);
                if (mCaInputStream != null) {
                    mCaInputStream.close();
                }

//                3.将证书导入到本地的证书密钥库中去
                KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                //这几行代码，貌似没有导入的操作？
                keyStore.load(null, null);
                keyStore.setCertificateEntry("123", certificate);

//                4.使用本地密钥库初始化信任管理器中去
                TrustManagerFactory trustManagerFactory
                        = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                trustManagerFactory.init(keyStore);

//                5.使用信任管理器得到X509TrustManager
                TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
                //这个位置，我直接取了数组的第一个元素，貌似不妥。
                X509TrustManager x509TrustManager = (X509TrustManager) trustManagers[0];

//                6.使用X509TrustManager校验服务端的证书，此方法不报异常即使校验成功
//                异常：CertPathValidatorException
                x509TrustManager.checkServerTrusted(chain, authType);

            } catch (IOException e) {
                e.printStackTrace();
            } catch (KeyStoreException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (CertificateException e) {
//                发生异常，就用设备本身默认的信任管理器进行校验
//                这样可能存在危险，经过测试如果加上这句话，fiddler可以正常抓包的
//                这是因为fiddler抓包之前，会在客户端安装一个证书，如果指定的证书校验失败
//                就是默认使用这个证书匹配，结果能够和fiddler匹配成功。
                try {
                    TrustManagerFactory trustManagerFactory
                            = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                    //初始化手机本身默认的证书信任管理器用于认证。
                    trustManagerFactory.init((KeyStore) null);
                    TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
                    X509TrustManager x509TrustManager = chooseTrustManager(trustManagers);
                    x509TrustManager.checkServerTrusted(chain, authType);
                } catch (NoSuchAlgorithmException e1) {
                    e1.printStackTrace();
                } catch (KeyStoreException e1) {
                    e1.printStackTrace();
                }
            }
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            //这里如果传空会报异常
            return new X509Certificate[0];
        }
    };

    private static X509TrustManager chooseTrustManager(TrustManager[] trustManagers) {
        for (TrustManager trustManager : trustManagers) {
            if (trustManager instanceof X509TrustManager) {
                return (X509TrustManager) trustManager;
            }
        }
        return null;
    }
}
