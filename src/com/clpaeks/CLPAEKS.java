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

//Our's CLPAEKS scheme
public class CLPAEKS {
    public static Pairing bp = PairingFactory.getPairing("a.properties");

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
        Element gt = bp.pairing(g,g).getImmutable();
        Properties ppProp = new Properties();
        ppProp.setProperty("g", Base64.getEncoder().encodeToString(g.toBytes()));
        ppProp.setProperty("gt", Base64.getEncoder().encodeToString(gt.toBytes()));
        storePropToFile(ppProp, ppFileName);
    }

    public static void keygen(String pairingParametersFileName, String idSender, String idReceiver, String mskFileName, String skFileName, String pkFileName, String ppFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties ppProp = loadPropFromFile(ppFileName);
        String gString = ppProp.getProperty("g");
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();
        String gtString = ppProp.getProperty("gt");
        Element gt = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(gtString)).getImmutable();

        byte[] idReceiverHash = sha512(idReceiver.getBytes());
        Element QID_Receiver = bp.getG1().newElementFromHash(idReceiverHash, 0, idReceiverHash.length).getImmutable();
        byte[] idSenderHash = sha512(idSender.getBytes());
        Element QID_Sender = bp.getG1().newElementFromHash(idSenderHash, 0, idSenderHash.length).getImmutable();

        Properties mskProp = loadPropFromFile(mskFileName);
        String y_String = mskProp.getProperty("y");
        Element y = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(y_String)).getImmutable();

        Element SK_Receiver_0 = bp.getZr().newRandomElement().getImmutable();
        Element SK_Receiver_1 = QID_Receiver.powZn(y).getImmutable();
        Element SK_Sender_0 = bp.getZr().newRandomElement().getImmutable();
        Element SK_Sender_1 = QID_Sender.powZn(y).getImmutable();

        Properties skProp = new Properties();
        skProp.setProperty("SK_Receiver_0", Base64.getEncoder().encodeToString(SK_Receiver_0.toBytes()));
        skProp.setProperty("SK_Receiver_1", Base64.getEncoder().encodeToString(SK_Receiver_1.toBytes()));
        skProp.setProperty("SK_Sender_0", Base64.getEncoder().encodeToString(SK_Sender_0.toBytes()));
        skProp.setProperty("SK_Sender_1", Base64.getEncoder().encodeToString(SK_Sender_1.toBytes()));
        storePropToFile(skProp, skFileName);

        Element PK_Receiver = gt.powZn(SK_Receiver_0).getImmutable();
        Element PK_Sender = gt.powZn(SK_Sender_0).getImmutable();

        Properties pkProp = new Properties();
        pkProp.setProperty("PK_Receiver", Base64.getEncoder().encodeToString(PK_Receiver.toBytes()));
        pkProp.setProperty("PK_Sender", Base64.getEncoder().encodeToString(PK_Sender.toBytes()));
        storePropToFile(pkProp, pkFileName);
    }

    public static void encrypt(String pairingParametersFileName, String ppFileName, String keyword, String idSender, String idReceiver, String skFileName, String pkFileName, String ctFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties ppProp = loadPropFromFile(ppFileName);
        String gString = ppProp.getProperty("g");
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();

        Properties pkProp = loadPropFromFile(pkFileName);
        String PK_Receiver_String = pkProp.getProperty("PK_Receiver");
        Element PK_Receiver = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(PK_Receiver_String)).getImmutable();

        byte[] idReceiverHash = sha512(idReceiver.getBytes());
        Element QIDReceiver = bp.getG1().newElementFromHash(idReceiverHash, 0, idReceiverHash.length).getImmutable();

        Properties skProp = loadPropFromFile(skFileName);
        String SK_Sender_0_String = skProp.getProperty("SK_Sender_0");
        Element SK_Sender_0 = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(SK_Sender_0_String)).getImmutable();
        String SK_Sender_1_String = skProp.getProperty("SK_Sender_1");
        Element SK_Sender_1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(SK_Sender_1_String)).getImmutable();

        Element kPairing = bp.pairing(SK_Sender_1, QIDReceiver).getImmutable();
        Element kPow = PK_Receiver.powZn(SK_Sender_0).getImmutable();
        Element kGT = kPairing.mul(kPow).getImmutable();
        byte[] kMerge1 = merge(idSender.getBytes(), idReceiver.getBytes());
        byte[] kMerge2 = merge(kMerge1, kGT.toBytes());
        Element k = bp.getZr().newElementFromHash(kMerge2, 0, kMerge2.length).getImmutable();

        Element a = bp.getZr().newRandomElement().getImmutable();
        byte[] messageHashBytes = sha512(keyword.getBytes());
        Element messageHash = bp.getG1().newElementFromHash(messageHashBytes, 0, messageHashBytes.length).getImmutable();

        //C1
        Element C1 = bp.pairing(g, messageHash).powZn(a.mul(k)).getImmutable();

        //C2
        Element C2 = g.powZn(a).getImmutable();

        //C3
        Element C3 = g.powZn(a.div(k)).getImmutable();

        Properties ctProp = new Properties();
        ctProp.setProperty("C1", Base64.getEncoder().encodeToString(C1.toBytes()));
        ctProp.setProperty("C2", Base64.getEncoder().encodeToString(C2.toBytes()));
        ctProp.setProperty("C3", Base64.getEncoder().encodeToString(C3.toBytes()));
        storePropToFile(ctProp, ctFileName);
    }


    public static void authorize(String pairingParametersFileName, String ppFileName, String keyword, String idSender, String idReceiver, String skFileName, String pkFileName, String tdFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties skProp = loadPropFromFile(skFileName);
        String SK_Receiver_0_String = skProp.getProperty("SK_Receiver_0");
        Element SK_Receiver_0 = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(SK_Receiver_0_String)).getImmutable();
        String SK_Receiver_1_String = skProp.getProperty("SK_Receiver_1");
        Element SK_Receiver_1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(SK_Receiver_1_String)).getImmutable();


        Properties pkProp = loadPropFromFile(pkFileName);
        String PK_Sender_String = pkProp.getProperty("PK_Sender");
        Element PK_Sender = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(PK_Sender_String)).getImmutable();

        byte[] idSenderHash = sha512(idSender.getBytes());
        Element QIDSender = bp.getG1().newElementFromHash(idSenderHash, 0, idSenderHash.length).getImmutable();

        Element kPairing = bp.pairing(SK_Receiver_1, QIDSender).getImmutable();
        Element kPow = PK_Sender.powZn(SK_Receiver_0).getImmutable();
        Element kGT = kPairing.mul(kPow).getImmutable();
        byte[] kMerge1 = merge(idSender.getBytes(), idReceiver.getBytes());
        byte[] kMerge2 = merge(kMerge1, kGT.toBytes());
        Element k = bp.getZr().newElementFromHash(kMerge2, 0, kMerge2.length).getImmutable();

        Element beta = bp.getZr().newRandomElement().getImmutable();
        Element gamma = bp.getZr().newRandomElement().getImmutable();
        byte[] messageHashBytes = sha512(keyword.getBytes());
        Element messageHash = bp.getG1().newElementFromHash(messageHashBytes, 0, messageHashBytes.length).getImmutable();

        //td1
        Element td1exp = beta.add(gamma.div(k)).getImmutable();
        Element td1 = messageHash.powZn(td1exp);

        //td2
        Element td2exp = k.mul(k).mul(k).div(beta).sub(gamma).getImmutable();
        Element td2 = messageHash.powZn(td2exp);

        //td3
        Element td3 = beta.div(k).add(k.div(beta)).getImmutable();

        Properties tdProp = new Properties();
        tdProp.setProperty("td1", Base64.getEncoder().encodeToString(td1.toBytes()));
        tdProp.setProperty("td2", Base64.getEncoder().encodeToString(td2.toBytes()));
        tdProp.setProperty("td3", Base64.getEncoder().encodeToString(td3.toBytes()));
        storePropToFile(tdProp, tdFileName);
    }

    public static void test(String pairingParametersFileName, String ctFileName, String tdFileName) {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties ctProp = loadPropFromFile(ctFileName);
        String C1String = ctProp.getProperty("C1");
        Element C1 = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(C1String)).getImmutable();
        String C2String = ctProp.getProperty("C2");
        Element C2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C2String)).getImmutable();
        String C3String = ctProp.getProperty("C3");
        Element C3 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C3String)).getImmutable();

        Properties tdProp = loadPropFromFile(tdFileName);
        String td1String = tdProp.getProperty("td1");
        Element td1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(td1String)).getImmutable();
        String td2String = tdProp.getProperty("td2");
        Element td2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(td2String)).getImmutable();
        String td3String = tdProp.getProperty("td3");
        Element td3 = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(td3String)).getImmutable();

        Element left = bp.pairing(C2, td1).mul(bp.pairing(C3, td2)).getImmutable();
        Element right = C1.powZn(td3).getImmutable();

        boolean res = false;
        res = left.isEqual(right);
        System.out.println("Test result:" + res);
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

    public static void testFile() throws NoSuchAlgorithmException {

        String dir = "dataCLEET/";
        String pairingParametersFileName = "a.properties";
        String ppFileName = dir + "pp.properties";
        long startTime = System.nanoTime();
        for (int i = 0; i < 1000; i++) {
            Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
            loadPropFromFile(ppFileName);
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

    public static void testHz() throws NoSuchAlgorithmException {
        String pairingParametersFileName = "a.properties";
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        byte[] idSenderHash = sha1(pairingParametersFileName);
        long startTime = System.nanoTime();
        for (int i = 0; i < 1000; i++) {
            Element QID_Sender = bp.getZr().newElementFromHash(idSenderHash, 0, idSenderHash.length).getImmutable();
        }
        long endTime1 = System.nanoTime();
        long last1 = (endTime1 - startTime)/1000000;
        System.out.println("Time:" + last1 + "ms");

    }

}


