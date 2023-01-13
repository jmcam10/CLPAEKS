package com.clpaeks;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Properties;

//Shiraly et al.'s CLPAEKS scheme
public class Shiraly_CLPAEKS {

    public static byte[] merge(byte[] a, byte b[]) {
        int lengthA = a.length, lengthB = b.length;
        byte[] c = new byte[lengthA + lengthB];
        for (int i = 0; i < lengthA; i++) {
            c[i] = a[i];
        }
        for (int i = 0; i < lengthB; i++) {
            c[i + lengthA] = b[i];
        }
        return c;
    }

    public static byte[] sha512(byte[] content) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        digest.update(content);
        return digest.digest();
    }

    public static byte[] sha256(byte[] content) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(content);
        return digest.digest();
    }

    public static byte[] sha1(String content) throws NoSuchAlgorithmException {
        MessageDigest instance = MessageDigest.getInstance("SHA-1");
        instance.update(content.getBytes());
        return instance.digest();
    }

    public static byte[] sha1(byte[] content) throws NoSuchAlgorithmException {
        MessageDigest instance = MessageDigest.getInstance("SHA-1");
        instance.update(content);
        return instance.digest();
    }

    public static void storePropToFile(Properties prop, String fileName){
        FileOutputStream out = null;
        try{
            out = new FileOutputStream(fileName);
            prop.store(out, null);
            out.close();
        }
        catch (IOException e) {
            e.printStackTrace();
            System.out.println(fileName + " save failed!");
            System.exit(-1);
        }
    }

    public static Properties loadPropFromFile(String fileName) {
        Properties prop = new Properties();
        try (FileInputStream in = new FileInputStream(fileName)){
            prop.load(in);
        }
        catch (IOException e){
            e.printStackTrace();
            System.out.println(fileName + " load failed!");
            System.exit(-1);
        }
        return prop;
    }

    public static void setup(String pairingParametersFileName, String ppFileName, String mskFileName) {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Element y = bp.getZr().newRandomElement().getImmutable();
        Properties mskProp = new Properties();
        mskProp.setProperty("y", Base64.getEncoder().encodeToString(y.toBytes()));
        storePropToFile(mskProp, mskFileName);

        Element g = bp.getG1().newRandomElement().getImmutable();
        Element mpk = g.powZn(y).getImmutable();
        Properties ppProp = new Properties();
        ppProp.setProperty("g", Base64.getEncoder().encodeToString(g.toBytes()));
        ppProp.setProperty("mpk", Base64.getEncoder().encodeToString(mpk.toBytes()));
        storePropToFile(ppProp, ppFileName);
    }

    public static void keygen(String pairingParametersFileName, String idSender, String idReceiver, String mskFileName, String skFileName, String pkFileName, String ppFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties ppProp = loadPropFromFile(ppFileName);
        String gString = ppProp.getProperty("g");
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();


        Properties mskProp = loadPropFromFile(mskFileName);
        String y_String = mskProp.getProperty("y");
        Element y = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(y_String)).getImmutable();

        Element r_s = bp.getZr().newRandomElement().getImmutable();
        Element r_r = bp.getZr().newRandomElement().getImmutable();
        Element R_s = g.powZn(r_s).getImmutable();
        Element R_r = g.powZn(r_r).getImmutable();
        byte[] sk_s_bytes = sha512(merge(idSender.getBytes(), R_s.toBytes()));
        byte[] sk_r_bytes = sha512(merge(idReceiver.getBytes(), R_r.toBytes()));
        Element H_s = bp.getZr().newElementFromHash(sk_s_bytes, 0, sk_s_bytes.length).getImmutable();
        Element H_r = bp.getZr().newElementFromHash(sk_r_bytes, 0, sk_r_bytes.length).getImmutable();

        Element SK_Receiver_0 = bp.getZr().newRandomElement().getImmutable();
        Element SK_Receiver_1 = r_r.add(H_r.mul(y)).getImmutable();
        Element SK_Sender_0 = bp.getZr().newRandomElement().getImmutable();
        Element SK_Sender_1 = r_s.add(H_s.mul(y)).getImmutable();

        Properties skProp = new Properties();
        skProp.setProperty("SK_Receiver_0", Base64.getEncoder().encodeToString(SK_Receiver_0.toBytes()));
        skProp.setProperty("SK_Receiver_1", Base64.getEncoder().encodeToString(SK_Receiver_1.toBytes()));
        skProp.setProperty("SK_Sender_0", Base64.getEncoder().encodeToString(SK_Sender_0.toBytes()));
        skProp.setProperty("SK_Sender_1", Base64.getEncoder().encodeToString(SK_Sender_1.toBytes()));
        storePropToFile(skProp, skFileName);

        Element PK_Receiver_0 = g.powZn(SK_Receiver_0).getImmutable();
        Element PK_Sender_0 = g.powZn(SK_Sender_0).getImmutable();

        Properties pkProp = new Properties();
        pkProp.setProperty("PK_Receiver_0", Base64.getEncoder().encodeToString(PK_Receiver_0.toBytes()));
        pkProp.setProperty("PK_Receiver_1", Base64.getEncoder().encodeToString(R_r.toBytes()));
        pkProp.setProperty("PK_Sender_0", Base64.getEncoder().encodeToString(PK_Sender_0.toBytes()));
        pkProp.setProperty("PK_Sender_1", Base64.getEncoder().encodeToString(R_s.toBytes()));
        storePropToFile(pkProp, pkFileName);
    }

    public static void encrypt(String pairingParametersFileName, String ppFileName, String keyword, String idSender, String idReceiver, String skFileName, String pkFileName, String ctFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties ppProp = loadPropFromFile(ppFileName);
        String gString = ppProp.getProperty("g");
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();
        String mpkString = ppProp.getProperty("mpk");
        Element mpk = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(mpkString)).getImmutable();

        Properties pkProp = loadPropFromFile(pkFileName);
        String PK_Sender_0_String = pkProp.getProperty("PK_Sender_0");
        Element PK_Sender_0 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PK_Sender_0_String)).getImmutable();
        String PK_Sender_1_String = pkProp.getProperty("PK_Sender_1");
        Element PK_Sender_1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PK_Sender_1_String)).getImmutable();
        String PK_Receiver_0_String = pkProp.getProperty("PK_Receiver_0");
        Element PK_Receiver_0 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PK_Receiver_0_String)).getImmutable();
        String PK_Receiver_1_String = pkProp.getProperty("PK_Receiver_1");
        Element PK_Receiver_1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PK_Receiver_1_String)).getImmutable();

        byte[] idReceiverHash = sha512(merge(idReceiver.getBytes(), PK_Receiver_1.toBytes()));
        Element QIDReceiver = bp.getZr().newElementFromHash(idReceiverHash, 0, idReceiverHash.length).getImmutable();

        Properties skProp = loadPropFromFile(skFileName);
        String SK_Sender_0_String = skProp.getProperty("SK_Sender_0");
        Element SK_Sender_0 = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(SK_Sender_0_String)).getImmutable();
        String SK_Sender_1_String = skProp.getProperty("SK_Sender_1");
        Element SK_Sender_1 = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(SK_Sender_1_String)).getImmutable();

        Element kPow1 = (PK_Receiver_1.mul(mpk.powZn(QIDReceiver))).powZn(SK_Sender_1).getImmutable();
        Element kPow2 = PK_Receiver_0.powZn(SK_Sender_0).getImmutable();
        Element r = bp.getZr().newRandomElement().getImmutable();

        //C1
        Element C1 = g.powZn(r).getImmutable();

        //C2
        byte[] h1ID = merge(merge(idSender.getBytes(), PK_Sender_0.toBytes()),merge(idReceiver.getBytes(), PK_Receiver_0.toBytes()));
        byte[] h1Share = merge(kPow1.toBytes(), kPow2.toBytes());
        byte[] h1Bytes = merge(merge(h1ID, h1Share), keyword.getBytes());
        byte[] h1BytesHash = sha512(h1Bytes);
        Element h1 = bp.getZr().newElementFromHash(h1BytesHash, 0, h1BytesHash.length).getImmutable();
        byte[] h2Hash = sha512(merge(h1.toBytes(), C1.toBytes()));
        Element h2 = bp.getZr().newElementFromHash(h2Hash, 0, h2Hash.length).getImmutable();
        Element C2 = g.powZn(h2.mul(r)).getImmutable();

        Properties ctProp = new Properties();
        ctProp.setProperty("C1", Base64.getEncoder().encodeToString(C1.toBytes()));
        ctProp.setProperty("C2", Base64.getEncoder().encodeToString(C2.toBytes()));
        storePropToFile(ctProp, ctFileName);
    }


    public static void authorize(String pairingParametersFileName, String ppFileName, String keyword, String idSender, String idReceiver, String skFileName, String pkFileName, String tdFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties ppProp = loadPropFromFile(ppFileName);
        String gString = ppProp.getProperty("g");
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();
        String mpkString = ppProp.getProperty("mpk");
        Element mpk = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(mpkString)).getImmutable();

        Properties pkProp = loadPropFromFile(pkFileName);
        String PK_Sender_0_String = pkProp.getProperty("PK_Sender_0");
        Element PK_Sender_0 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PK_Sender_0_String)).getImmutable();
        String PK_Sender_1_String = pkProp.getProperty("PK_Sender_1");
        Element PK_Sender_1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PK_Sender_1_String)).getImmutable();
        String PK_Receiver_0_String = pkProp.getProperty("PK_Receiver_0");
        Element PK_Receiver_0 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PK_Receiver_0_String)).getImmutable();
        String PK_Receiver_1_String = pkProp.getProperty("PK_Receiver_1");
        Element PK_Receiver_1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PK_Receiver_1_String)).getImmutable();

        byte[] idSenderHash = sha512(merge(idSender.getBytes(), PK_Sender_1.toBytes()));
        Element QIDSender = bp.getZr().newElementFromHash(idSenderHash, 0, idSenderHash.length).getImmutable();

        Properties skProp = loadPropFromFile(skFileName);
        String SK_Receiver_0_String = skProp.getProperty("SK_Receiver_0");
        Element SK_Receiver_0 = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(SK_Receiver_0_String)).getImmutable();
        String SK_Receiver_1_String = skProp.getProperty("SK_Receiver_1");
        Element SK_Receiver_1 = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(SK_Receiver_1_String)).getImmutable();

        Element kPow1 = (PK_Sender_1.mul(mpk.powZn(QIDSender))).powZn(SK_Receiver_1).getImmutable();
        Element kPow2 = PK_Sender_0.powZn(SK_Receiver_0).getImmutable();

        byte[] h1ID = merge(merge(idSender.getBytes(), PK_Sender_0.toBytes()),merge(idReceiver.getBytes(), PK_Receiver_0.toBytes()));
        byte[] h1Share = merge(kPow1.toBytes(), kPow2.toBytes());
        byte[] h1Bytes = merge(merge(h1ID, h1Share), keyword.getBytes());
        byte[] h1BytesHash = sha512(h1Bytes);
        Element td = bp.getZr().newElementFromHash(h1BytesHash, 0, h1BytesHash.length).getImmutable();

        Properties tdProp = new Properties();
        tdProp.setProperty("td", Base64.getEncoder().encodeToString(td.toBytes()));
        storePropToFile(tdProp, tdFileName);
    }

    public static void test(String pairingParametersFileName, String ctFileName, String tdFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties ctProp = loadPropFromFile(ctFileName);
        String C1String = ctProp.getProperty("C1");
        Element C1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C1String)).getImmutable();
        String C2String = ctProp.getProperty("C2");
        Element C2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C2String)).getImmutable();

        Properties tdProp = loadPropFromFile(tdFileName);
        String tdString = tdProp.getProperty("td");
        Element td = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(tdString)).getImmutable();

        byte[] h2Hash = sha512(merge(td.toBytes(), C1.toBytes()));
        Element h2 = bp.getZr().newElementFromHash(h2Hash, 0, h2Hash.length).getImmutable();
        Element right = C1.powZn(h2).getImmutable();

        boolean res = false;
        res = C2.isEqual(right);
        System.out.println("Test result:" + res);
//        System.out.println("Time:" + last + "ms");
    }


    public static void main(String[] args) throws Exception {

        String idSender = "alice@example.com";
        String idReceiver = "bob@example.com";
        String keyword = "keyword";

        String dir = "data_CLPAEKS/";
        String pairingParametersFileName = "a.properties";
        String ppFileName = dir + "pp.properties";
        String mskFileName = dir + "msk.properties";
        String ctFileName = dir + "ct.properties";
        String skFileName = dir + "sk.properties";
        String pkFileName = dir + "pk.properties";
        String tdFileName = dir + "td.properties";
        setup(pairingParametersFileName, ppFileName, mskFileName);
        keygen(pairingParametersFileName, idSender, idReceiver, mskFileName, skFileName, pkFileName, ppFileName);
        encrypt(pairingParametersFileName, ppFileName, keyword, idSender, idReceiver, skFileName, pkFileName, ctFileName);
        authorize(pairingParametersFileName, ppFileName, keyword, idSender, idReceiver, skFileName, pkFileName, tdFileName);
        test(pairingParametersFileName, ctFileName, tdFileName);
//        testEnc();
//        testAut();
//        testTest();
//        testP1();
//        testPow();
//        testInv();
//        testMul();
//        testHp();
    }

    public static void testEnc() throws NoSuchAlgorithmException {
        String idSender = "alice@example.com";
        String idReceiver = "bob@example.com";
        String keyword = "keyword";

        String dir = "data_CLPAEKS/";
        String pairingParametersFileName = "a.properties";
        String ppFileName = dir + "pp.properties";
        String mskFileName = dir + "msk.properties";
        String ctFileName = dir + "ct.properties";
        String skFileName = dir + "sk.properties";
        String pkFileName = dir + "pk.properties";
        String tdFileName = dir + "td.properties";
        long startTime = System.nanoTime();

        for (int j = 0; j < 100; j++) {
            encrypt(pairingParametersFileName, ppFileName, keyword, idSender, idReceiver, skFileName, pkFileName, ctFileName);
        }
        long endTime1 = System.nanoTime();
        long last1 = (endTime1 - startTime)/1000000;
        System.out.println("Time" + last1 + "ms");

    }

    public static void testAut() throws NoSuchAlgorithmException {
        String idSender = "alice@example.com";
        String idReceiver = "bob@example.com";
        String keyword = "keyword";

        String dir = "data_CLPAEKS/";
        String pairingParametersFileName = "a.properties";
        String ppFileName = dir + "pp.properties";
        String mskFileName = dir + "msk.properties";
        String ctFileName = dir + "ct.properties";
        String skFileName = dir + "sk.properties";
        String pkFileName = dir + "pk.properties";
        String tdFileName = dir + "td.properties";
        long startTime = System.nanoTime();

        for (int j = 0; j < 100; j++) {
            authorize(pairingParametersFileName, ppFileName, keyword, idSender, idReceiver, skFileName, pkFileName, tdFileName);
        }
        long endTime1 = System.nanoTime();
        long last1 = (endTime1 - startTime)/1000000;
        System.out.println("Time" + last1 + "ms");

    }

    public static void testTest() throws NoSuchAlgorithmException {
        String idSender = "alice@example.com";
        String idReceiver = "bob@example.com";
        String keyword = "keyword";

        String dir = "data_CLPAEKS/";
        String pairingParametersFileName = "a.properties";
        String ppFileName = dir + "pp.properties";
        String mskFileName = dir + "msk.properties";
        String ctFileName = dir + "ct.properties";
        String skFileName = dir + "sk.properties";
        String pkFileName = dir + "pk.properties";
        String tdFileName = dir + "td.properties";
        long startTime = System.nanoTime();

        for (int j = 0; j < 100; j++) {
            test(pairingParametersFileName, ctFileName, tdFileName);
        }
        long endTime1 = System.nanoTime();
        long last1 = (endTime1 - startTime)/1000000;
        System.out.println("Time"  + last1 + "ms");

    }


    public static void testP2() throws NoSuchAlgorithmException {
        String pairingParametersFileName = "a.properties";
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Element g1 = bp.getG1().newRandomElement().getImmutable();
        Element g2 = bp.getG2().newRandomElement().getImmutable();

        long startTime = System.nanoTime();
        for (int i = 0; i < 1000; i++) {
            bp.pairing(g1, g2);
        }
        long endTime1 = System.nanoTime();
        long last1 = (endTime1 - startTime)/1000000;
        System.out.println("Time:" + last1 + "ms");

    }

    public static void testP1() throws NoSuchAlgorithmException {
        String pairingParametersFileName = "a.properties";
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        long startTime = System.nanoTime();
        Element g1 = bp.getG1().newRandomElement().getImmutable();
        Element g1_ = bp.getG1().newRandomElement().getImmutable();
        Element g2 = bp.getG2().newRandomElement().getImmutable();

        for (int i = 0; i < 1000; i++) {
            bp.pairing(g1, g1_);
        }
        long endTime1 = System.nanoTime();
        long last1 = (endTime1 - startTime)/1000000;
        System.out.println("Time:" + last1 + "ms");

    }

    public static void testPow() throws NoSuchAlgorithmException {
        String pairingParametersFileName = "a.properties";
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Element g1 = bp.getG1().newRandomElement().getImmutable();
        Element a = bp.getZr().newRandomElement().getImmutable();
        Element gt = bp.getGT().newRandomElement().getImmutable();
        System.out.println(bp.getG1().getOrder());
        System.out.println(gt);
        long startTime = System.nanoTime();
        for (int i = 0; i < 1000; i++) {
            g1.powZn(a).getImmutable();
        }
        long endTime1 = System.nanoTime();
        long last1 = (endTime1 - startTime)/1000000;
        System.out.println("Time:" + last1 + "ms");

    }

    public static void testMul() throws NoSuchAlgorithmException {
        String pairingParametersFileName = "a.properties";
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Element g1 = bp.getG1().newRandomElement().getImmutable();
        Element g1_ = bp.getG1().newRandomElement().getImmutable();
        Element r = bp.getZr().newRandomElement().getImmutable();
        long startTime = System.nanoTime();
        for (int i = 0; i < 1000; i++) {
            g1.mul(g1_);
        }
        long endTime1 = System.nanoTime();
        long last1 = (endTime1 - startTime)/1000000;
        System.out.println("Time:" + last1 + "ms");

    }

    public static void testDiv() throws NoSuchAlgorithmException {
        String pairingParametersFileName = "a.properties";
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Element g1 = bp.getG1().newRandomElement().getImmutable();
        Element g2 = bp.getG1().newRandomElement().getImmutable();

        long startTime = System.nanoTime();
        for (int i = 0; i < 1000; i++) {
            g1.div(g2).getImmutable();
        }
        long endTime1 = System.nanoTime();
        long last1 = (endTime1 - startTime)/1000000;
        System.out.println("Time:" + last1 + "ms");

    }


    public static void testSha() throws NoSuchAlgorithmException {
        String pairingParametersFileName = "a.properties";
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        long startTime = System.nanoTime();

        for (int i = 0; i < 1000; i++) {
            byte[] idSenderHash = sha1(pairingParametersFileName);
            Element QID_Sender = bp.getG1().newElementFromHash(idSenderHash, 0, idSenderHash.length).getImmutable();
        }
        long endTime1 = System.nanoTime();
        long last1 = (endTime1 - startTime)/1000000;
        System.out.println("Time:" + last1 + "ms");

    }

    public static void testHp() throws NoSuchAlgorithmException {
        String pairingParametersFileName = "a.properties";
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        byte[] idSenderHash = sha1(pairingParametersFileName);
        long startTime = System.nanoTime();
        for (int i = 0; i < 1000; i++) {
            Element QID_Sender = bp.getG1().newElementFromHash(idSenderHash, 0, idSenderHash.length).getImmutable();
        }
        long endTime1 = System.nanoTime();
        long last1 = (endTime1 - startTime)/1000000;
        System.out.println("Time:" + last1 + "ms");

    }

}



