package test;
/*
 * Copyright (c) 1997, 2001, Oracle and/or its affiliates. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   - Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   - Neither the name of Oracle nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;

/**
 * This program executes the Diffie-Hellman key agreement protocol
 * between 2 parties: Alice and Bob.
 *
 * By default, preconfigured parameters (1024-bit prime modulus and base
 * generator used by SKIP) are used.
 * If this program is called with the "-gen" option, a new set of
 * parameters is created.
 */

public class DHKeyAgreement2 {

    private DHKeyAgreement2() {}

    public final static String sP = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6" +
            "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0" +
            "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70" +
            "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0" +
            "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708" +
            "DF1FB2BC2E4A4371";
	
	public final static String sG = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F" +
		    "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213" +
		    "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1" +
		    "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A" +
		    "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24" +
		    "855E6EEB22B3B2E5";
	
	
    public static void main(String argv[]) {
        try {
            DHKeyAgreement2 keyAgree = new DHKeyAgreement2();
            keyAgree.run();
        } catch (Exception e) {
            System.err.println("Error: " + e);
            System.exit(1);
        }
    }

    private void run() throws Exception {

        DHParameterSpec dhSkipParamSpec;
        // use some pre-generated, default DH parameters
        
        BigInteger p = new BigInteger(sP,16);
		BigInteger g = new BigInteger(sG,16);
		
		System.out.println("P " + sP.length() + " is: " + toHexString(p.toByteArray()));
		System.out.println("G " + sG.length() + " is: " + toHexString(g.toByteArray()));
        dhSkipParamSpec = new DHParameterSpec(p,g);
        /*
         * Alice creates her own DH key pair, using the DH parameters from
         * above
         */
        System.out.println("ALICE: Generate DH keypair ...");
        KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("DH");
        aliceKpairGen.initialize(dhSkipParamSpec);
        KeyPair aliceKpair = aliceKpairGen.generateKeyPair();

        // Alice creates and initializes her DH KeyAgreement object
        System.out.println("ALICE: Initialization ...");
        KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH");
        aliceKeyAgree.init(aliceKpair.getPrivate());

        // Alice encodes her public key, and sends it over to Bob.
        byte[] alicePubKeyEnc = aliceKpair.getPublic().getEncoded();
        System.out.println("Alice pub key size: " + alicePubKeyEnc.length);
        System.out.println("Alice pub key: " + toHexString(alicePubKeyEnc));
        
        byte[] alicePrivKeyEnc = aliceKpair.getPrivate().getEncoded();
		System.out.println("Alice priv key size: " + alicePrivKeyEnc.length);
        System.out.println("Alice priv key: " + toHexString(alicePrivKeyEnc));
        
        // Read bob pub key
        ServerSocket ss = new ServerSocket(5454);
        Socket accept = ss.accept();
        byte[] bobPubKeyEnc = readByteArrayFromSocket(accept);
        System.out.println("Read bob's pubkey: " + toHexString(bobPubKeyEnc));
        
        // Send Alice's pub key to Bob
        sendByteArrayToBob(alicePubKeyEnc);
        System.out.println("Sent Alice's pubkey");
      
        KeyFactory aliceKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(bobPubKeyEnc);
        PublicKey bobPubKey = aliceKeyFac.generatePublic(x509KeySpec);
        System.out.println("ALICE: Execute PHASE1 ...");
        aliceKeyAgree.doPhase(bobPubKey, true);

        
        byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();

        System.out.println("Alice secret: " + toHexString(aliceSharedSecret));
    }

	private void sendByteArrayToBob(byte[] alicePubKeyEnc) throws UnknownHostException, IOException
	{
		Socket sock = new Socket("localhost",5455);
        sock.getOutputStream().write(alicePubKeyEnc);
        sock.close();
	}

	private byte[] readByteArrayFromSocket(Socket accept) throws IOException
	{
		InputStream is = accept.getInputStream();
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		int nRead;
		byte[] data = new byte[16384];

		while ((nRead = is.read(data, 0, data.length)) != -1) 
		{
			buffer.write(data, 0, nRead);
			System.out.println("Read " + nRead + " bytes");
		}

		buffer.flush();
		accept.close();
		return buffer.toByteArray();
	}

    /*
     * Converts a byte to hex digit and writes to the supplied buffer
     */
    private void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
                            '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }

    /*
     * Converts a byte array to hex string
     */
    private String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();

        int len = block.length;

        for (int i = 0; i < len; i++) {
             byte2hex(block[i], buf);
             if (i < len-1) {
                 buf.append(":");
             }
        }
        return buf.toString();
    }
}
