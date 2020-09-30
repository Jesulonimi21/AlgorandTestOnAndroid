package com.example.testalgorandonandroid;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;

import android.os.Build;
import android.os.Bundle;
import android.util.Log;

import com.algorand.algosdk.account.Account;
import com.algorand.algosdk.algod.client.AlgodClient;
import com.algorand.algosdk.algod.client.ApiException;
import com.algorand.algosdk.algod.client.api.AlgodApi;
import com.algorand.algosdk.algod.client.auth.ApiKeyAuth;
import com.algorand.algosdk.algod.client.model.NodeStatus;
import com.algorand.algosdk.algod.client.model.TransactionID;
import com.algorand.algosdk.transaction.Transaction;
import com.algorand.algosdk.algod.client.model.TransactionParams;
import com.algorand.algosdk.crypto.Address;
import com.algorand.algosdk.crypto.Digest;
import com.algorand.algosdk.transaction.SignedTransaction;
import com.algorand.algosdk.util.Encoder;
import com.fasterxml.jackson.core.JsonProcessingException;

import java.math.BigInteger;


import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.security.GeneralSecurityException;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;

import java.security.Security;
import java.util.Iterator;


public class MainActivity extends AppCompatActivity {
    NodeStatus status;
    AlgodApi algodApiInstance;
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Security.removeProvider("BC");
        Security.insertProviderAt(new BouncyCastleProvider(), 0);
        String providerName = "BC";
        if (Security.getProvider(providerName) == null)
        {
            Log.d("algoDebug",providerName + " provider not installed");
        }
        else
        {
            Log.d("algoDebug",providerName + " is installed.");
        }

        final String ALGOD_API_ADDR = "https://testnet-algorand.api.purestake.io/ps1";
        final String ALGOD_API_TOKEN = "";

        AlgodClient client = new AlgodClient();
        client.addDefaultHeader("X-API-Key", ALGOD_API_TOKEN);
        client.setBasePath(ALGOD_API_ADDR);
        algodApiInstance = new AlgodApi(client);

        createAccountWithoutMnemonic();
        Account testAccount=createAccountWithMnemonic("degree secret exhibit pond toddler elbow message input can shield park educate gallery notice ten vintage scale close possible earn fat source define able fluid");

        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    sendAmountToAddress("ZY72XHRFKHPGPRN7MGN5FSPUZRGGZZ63HTEN7UGYV6LVZOKCEFOEN6TGHE",testAccount);
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
            }
        }).start();



            new  Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        getWalletBalance("ZY72XHRFKHPGPRN7MGN5FSPUZRGGZZ63HTEN7UGYV6LVZOKCEFOEN6TGHE");
                    } catch (ApiException e) {
                        e.printStackTrace();
                    }
                }
            }).start();


    }

    public void checkForProviderCapabilities(){
        Provider provider = Security.getProvider("BC");
        Iterator it = ((Provider) provider).keySet().iterator();
        while (it.hasNext())
        {
            String entry = (String)it.next();
            // this indicates the entry actually refers to another entry
            if (entry.startsWith("Alg.Alias."))
            {
                entry = entry.substring("Alg.Alias.".length());
            }
            String factoryClass = entry.substring(0, entry.indexOf('.'));
            String name = entry.substring(factoryClass.length() + 1);
            Log.d("algoDebug",factoryClass + ": " + name);
    }
}
    public static void createAccountWithoutMnemonic( ){
        Account myAccount1= null;

        try {
            myAccount1 = new Account();
            Log.d("algoDebug"," algod account address: " + myAccount1.getAddress());
            Log.d("algoDebug"," algod account MNEMONIC: " + myAccount1.toMnemonic());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            Log.d("algoDebug"," Eror while creating new account "+e);
        }
    }

    public static  Account createAccountWithMnemonic(String mnemonic){
        Account myAccount1= null;
        try {
            myAccount1 = new Account(mnemonic);
            Log.d("algoDebug"," algod account address: " + myAccount1.getAddress());
            Log.d("algoDebug"," algod account MNEMONIC: " + myAccount1.toMnemonic());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            Log.d("algoDebug"," Eror while creating new account "+e);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        return  myAccount1;
    }

    public  BigInteger getWalletBalance(String address) throws ApiException {
        com.algorand.algosdk.algod.client.model.Account account= algodApiInstance.accountInformation(address);
        Log.d("algoDebug","Amount of account is "+account.getAmount().divide(new BigInteger("1000000"))+" Algo");
        return account.getAmount();
    }

    public  void sendAmountToAddress(String address,Account src) throws NoSuchAlgorithmException {
        BigInteger feePerByte;
        String genesisID;
        Digest genesisHash;
        long firstRound = 0L;
        try {
            TransactionParams params = algodApiInstance.transactionParams();
            feePerByte = params.getFee();
            genesisHash = new Digest(params.getGenesishashb64());
            genesisID = params.getGenesisID();
            NodeStatus s = algodApiInstance.getStatus();
            firstRound = s.getLastRound().longValue();
        } catch (ApiException e) {
            throw new RuntimeException("Could not get params", e);
        }
        final String DEST_ADDR = address;
        long amount = 1000000L;
        long lastRound = firstRound + 1000;
        Transaction tx = new Transaction(src.getAddress(),
                new Address(DEST_ADDR),
                amount,
                firstRound,
                lastRound,
                genesisID,
                genesisHash);
        SignedTransaction signedTx = src.signTransactionWithFeePerByte(tx, feePerByte);

        try {
            byte[] encodedTxBytes = Encoder.encodeToMsgPack(signedTx);
            TransactionID id = algodApiInstance.rawTransaction(encodedTxBytes);
            System.out.println("Successfully sent tx with id: " + id);
            waitForConfirmation(algodApiInstance, id.getTxId());
        } catch (ApiException e) {
            Log.d("algoDebug","Exception when calling algod#rawTransaction: " + e.getResponseBody());
        } catch (JsonProcessingException e) {
            Log.d("algoDebug","Exception when calling algod#rawTransaction: " + e);
        } catch (java.lang.Exception e) {
            Log.d("algoDebug","Exception when calling algod#rawTransaction: " + e);
        }
    }

    public  void waitForConfirmation(AlgodApi algodApiInstance, String txID) throws Exception {
        long lastRound = algodApiInstance.getStatus().getLastRound().longValue();
        while (true) {
            try {
                // Check the pending tranactions
                com.algorand.algosdk.algod.client.model.Transaction pendingInfo = algodApiInstance.pendingTransactionInformation(txID);
                if (pendingInfo.getRound() != null && pendingInfo.getRound().longValue() > 0) {
                    // Got the completed Transaction
                    Log.d("algoDebug","Transaction " + pendingInfo.getTx() + " confirmed in round " + pendingInfo.getRound().longValue());
                    break;
                }
                lastRound++;
                algodApiInstance.waitForBlock(BigInteger.valueOf(lastRound));
            } catch (Exception e) {
                throw (e);
            }
        }
    }

//    FNAOTCKU2FMKGY5GOKNVG6CD7REFY6C4MNDG3TVAGHYEVELALDI2ACZPEU
//degree secret exhibit pond toddler elbow message input can shield park educate gallery notice ten vintage scale close possible earn fat source define able fluid

//    CZOIF2LCS2AIG4BDQGBQABZKBZL65D2HWPOONVLZ45QOIUB5WORZOI53U4
}
