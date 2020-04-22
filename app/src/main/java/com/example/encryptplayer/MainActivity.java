package com.example.encryptplayer;
//This PC\LG K10 (2017) Dual\Internal storage\Android\data\com.android.providers.media
import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;

import android.net.Uri;
import android.os.Build;
import android.os.Bundle;

import com.example.encryptplayer.encrypteplayer.DownloadAndEncryptFileTask;
import com.example.encryptplayer.encrypteplayer.EncryptedFileDataSource;
import com.example.encryptplayer.encrypteplayer.EncryptedFileDataSourceFactory;
import com.google.android.exoplayer2.DefaultLoadControl;
import com.google.android.exoplayer2.ExoPlaybackException;
import com.google.android.exoplayer2.ExoPlayer;
import com.google.android.exoplayer2.ExoPlayerFactory;
import com.google.android.exoplayer2.LoadControl;
import com.google.android.exoplayer2.SimpleExoPlayer;
import com.google.android.exoplayer2.Timeline;
import com.google.android.exoplayer2.extractor.DefaultExtractorsFactory;
import com.google.android.exoplayer2.extractor.ExtractorsFactory;
import com.google.android.exoplayer2.source.ExtractorMediaSource;
import com.google.android.exoplayer2.source.MediaSource;
import com.google.android.exoplayer2.source.TrackGroupArray;
import com.google.android.exoplayer2.trackselection.DefaultTrackSelector;
import com.google.android.exoplayer2.trackselection.TrackSelectionArray;
import com.google.android.exoplayer2.trackselection.TrackSelector;
import com.google.android.exoplayer2.ui.SimpleExoPlayerView;
import com.google.android.exoplayer2.upstream.DataSource;
import com.google.android.exoplayer2.upstream.DefaultBandwidthMeter;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity {
    private static final String AES_ALGORITHM = "AES";
    private static final String AES_TRANSFORMATION = "AES/CTR/NoPadding";
    private static final String PASSWORD = "1133";
    private static final byte[]SALT = {3, (byte) 253, (byte) 245, (byte) 149,86, (byte) 148, (byte) 148,43};
    private static final byte[]IV = {(byte) 139, (byte) 214,102,1, (byte) 150, (byte) 134, (byte) 236, (byte) 182,89,110,20,55, (byte) 243,120,76, (byte) 182};
    private static final String HASH_KEY = "SHA-256";

    private Cipher cipher;
    private SecretKeySpec secretKeySpec;
    private IvParameterSpec ivParameterSpec;

    SimpleExoPlayerView pw;
    private DefaultTrackSelector trackSelector;
    private SimpleExoPlayer player;
    private File mEncryptedFile;

    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        pw=findViewById(R.id.pw);
        try {

            secretKeySpec = generate(PASSWORD,SALT,HASH_KEY,AES_ALGORITHM);

            ivParameterSpec = new IvParameterSpec(IV);

            cipher =  createCipher(ivParameterSpec,secretKeySpec,AES_TRANSFORMATION);

        } catch (Exception e) {
            e.printStackTrace();
        }


        //initial EncryptedDataSource in ExoPlayer

        //http://saatmedia.ir:4020
        //File  mEncryptedFile = new File(getFilesDir(), "test");
       mEncryptedFile = new File(this.getExternalFilesDir(null), "test.mpg");

        try {
            // TODO:
            // you need to encrypt a video somehow with the same key and iv...  you can do that yourself and update
            // the ciphers, key and iv used in this demo, or to see it from top to bottom,
            // supply a url to a remote unencrypted file - this method will download and encrypt it
            // this first argument needs to be that url, not null or empty...
            new DownloadAndEncryptFileTask("http://192.168.10.40:2020",mEncryptedFile,cipher).execute();
        } catch (Exception e) {
            e.printStackTrace();
        }

        setPlayer();

    }

    public void setPlayer()
    {
        String path=mEncryptedFile.getPath();
        Uri uri=Uri.parse(path);
        LoadControl loadControl=new DefaultLoadControl();
        TrackSelector trackSelector=new DefaultTrackSelector();

        SimpleExoPlayer simpleExoPlayer= ExoPlayerFactory.newSimpleInstance(this,
                trackSelector,loadControl);

        DataSource.Factory encryptedFileDataSource  = new EncryptedFileDataSourceFactory(cipher,secretKeySpec,ivParameterSpec,new DefaultBandwidthMeter());

        ExtractorsFactory extractorsFactory = new DefaultExtractorsFactory();

        MediaSource videoSource = new ExtractorMediaSource(uri, encryptedFileDataSource, extractorsFactory, null, null);

        //MediaSource mediaSource=new ProgressiveMediaSource
               // .Factory(encryptedFileDataSource).createMediaSource(uri);

       /* MediaSource mediaSource=new ExtractorMediaSource(uri,
                encryptedFileDataSource, new DefaultExtractorsFactory(), null, null);*/

        pw.setPlayer(simpleExoPlayer);
        simpleExoPlayer.prepare(videoSource);
        simpleExoPlayer.setPlayWhenReady(true);

        simpleExoPlayer.addListener(new ExoPlayer.EventListener() {
            @Override
            public void onTimelineChanged(Timeline timeline, Object manifest) {

            }

            @Override
            public void onTracksChanged(TrackGroupArray trackGroups, TrackSelectionArray trackSelections) {

            }

            @Override
            public void onLoadingChanged(boolean isLoading) {

            }

            @Override
            public void onPlayerStateChanged(boolean playWhenReady, int playbackState) {

            }

            @Override
            public void onPlayerError(ExoPlaybackException error) {
                System.out.println(error.getMessage());
            }

            @Override
            public void onPositionDiscontinuity() {

            }
        });
    }

    //region Cipher
    private Cipher createCipher(IvParameterSpec mIvParameterSpec, SecretKeySpec mSecretKeySpec,String transformation) throws Exception {
        Cipher mCipher = Cipher.getInstance(transformation);
        mCipher.init(Cipher.DECRYPT_MODE, mSecretKeySpec, mIvParameterSpec);
        return mCipher;
    }

    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    private SecretKeySpec generate(String password, byte[] salt, String hashKey, String algoritm) throws Exception {
        MessageDigest md = MessageDigest.getInstance(hashKey);
        md.update(salt);
        byte[] key = md.digest(password.getBytes(StandardCharsets.UTF_8));
        return new SecretKeySpec(key, algoritm);
    }
    //endregion

  /*  private void prepareExoPlayerFromFileUri(Uri uri) {

        try {
            BandwidthMeter bandwidthMeter = new DefaultBandwidthMeter();
            videoTrackSelectionFactory = new AdaptiveTrackSelection.Factory(bandwidthMeter);
            trackSelector = new DefaultTrackSelector(videoTrackSelectionFactory);

            // 2. Create a default LoadControl
            LoadControl loadControl = new DefaultLoadControl();

            // 3. Create the player
            player = ExoPlayerFactory.newSimpleInstance(this, trackSelector, loadControl);
            player.addListener(this);
            simpleExoPlayerView.setPlayer(player);
            DataSpec dataSpec = new DataSpec(uri);
            Cipher aes = Cipher.getInstance("ARC4");
            aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec("secretkey".getBytes(), "ARC4"));
            final EncryptedFileDataSource fileDataSource = new EncryptedFileDataSource(aes, new TransferListener<EncryptedFileDataSource>() {
                @Override
                public void onTransferStart(EncryptedFileDataSource source, DataSpec dataSpec) {

                }

                @Override
                public void onBytesTransferred(EncryptedFileDataSource source, int bytesTransferred) {

                }

                @Override
                public void onTransferEnd(EncryptedFileDataSource source) {

                }
            });
            try {
                fileDataSource.open(dataSpec);
            } catch (Exception e) {
                e.printStackTrace();
            }

            DataSource.Factory factory = new DataSource.Factory() {
                @Override
                public DataSource createDataSource() {
                    return fileDataSource;
                }
            };
            MediaSource videoSource = new ExtractorMediaSource(fileDataSource.getUri(),
                    factory, new DefaultExtractorsFactory(), null, null);

            player.prepare(videoSource);
            simpleExoPlayerView.requestFocus();
            player.setPlayWhenReady(true);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }*/
}
