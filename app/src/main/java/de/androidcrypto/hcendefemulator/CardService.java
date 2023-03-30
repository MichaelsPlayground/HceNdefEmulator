package de.androidcrypto.hcendefemulator;

import android.content.Context;
import android.content.Intent;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.util.Log;
import android.widget.Toast;

import java.math.BigInteger;
import java.nio.charset.Charset;

/**
 * Created by justin.ribeiro on 10/27/2014.
 *
 * The following definitions are based on two things:
 *   1. NFC Forum Type 4 Tag Operation Technical Specification, version 3.0 2014-07-30
 *   2. APDU example in libnfc: http://nfc-tools.org/index.php?title=Libnfc:APDU_example
 *
 */
public class CardService extends HostApduService {

    private static final String TAG = "HostApduService";

    //
    // We use the default AID from the HCE Android documentation
    // https://developer.android.com/guide/topics/connectivity/nfc/hce.html
    //
    // Ala... <aid-filter android:name="F0394148148100" />
    //
    private static final byte[] APDU_SELECT = {
            (byte) 0x00, // CLA	- Class - Class of instruction
            (byte) 0xA4, // INS	- Instruction - Instruction code
            (byte) 0x04, // P1	- Parameter 1 - Instruction parameter 1
            (byte) 0x00, // P2	- Parameter 2 - Instruction parameter 2
            (byte) 0x07, // Lc field	- Number of bytes present in the data field of the command
            (byte) 0xD2, (byte) 0x76, (byte) 0x00, (byte) 0x00, (byte) 0x85, (byte) 0x01, (byte) 0x01, // NDEF Tag Application name D2 76 00 00 85 01 01
            (byte) 0x00  // Le field	- Maximum number of bytes expected in the data field of the response to the command
    };

    private static final byte[] CAPABILITY_CONTAINER = {
            (byte) 0x00, // CLA	- Class - Class of instruction
            (byte) 0xa4, // INS	- Instruction - Instruction code
            (byte) 0x00, // P1	- Parameter 1 - Instruction parameter 1
            (byte) 0x0c, // P2	- Parameter 2 - Instruction parameter 2
            (byte) 0x02, // Lc field	- Number of bytes present in the data field of the command
            (byte) 0xe1, (byte) 0x03 // file identifier of the CC file
    };

    private static final byte[] READ_CAPABILITY_CONTAINER = {
            (byte) 0x00, // CLA	- Class - Class of instruction
            (byte) 0xb0, // INS	- Instruction - Instruction code
            (byte) 0x00, // P1	- Parameter 1 - Instruction parameter 1
            (byte) 0x00, // P2	- Parameter 2 - Instruction parameter 2
            (byte) 0x0f  // Lc field	- Number of bytes present in the data field of the command
    };

    // In the scenario that we have done a CC read, the same byte[] match
    // for ReadBinary would trigger and we don't want that in succession
    private boolean READ_CAPABILITY_CONTAINER_CHECK = false;

    private static final byte[] READ_CAPABILITY_CONTAINER_RESPONSE = {
            (byte) 0x00, (byte) 0x0F, // CCLEN length of the CC file
            (byte) 0x20, // Mapping Version 2.0
            (byte) 0x00, (byte) 0x3B, // MLe maximum 59 bytes R-APDU data size
            (byte) 0x00, (byte) 0x34, // MLc maximum 52 bytes C-APDU data size
            (byte) 0x04, // T field of the NDEF File Control TLV
            (byte) 0x06, // L field of the NDEF File Control TLV
            (byte) 0xE1, (byte) 0x04, // File Identifier of NDEF file
            (byte) 0x00, (byte) 0x32, // Maximum NDEF file size of 50 bytes
            (byte) 0x00, // Read access without any security
            (byte) 0x00, // Write access without any security
            (byte) 0x90, (byte) 0x00 // A_OKAY
    };

    private static final byte[] NDEF_SELECT = {
            (byte) 0x00, // CLA	- Class - Class of instruction
            (byte) 0xa4, // Instruction byte (INS) for Select command
            (byte) 0x00, // Parameter byte (P1), select by identifier
            (byte) 0x0c, // Parameter byte (P1), select by identifier
            (byte) 0x02, // Lc field	- Number of bytes present in the data field of the command
            (byte) 0xE1, (byte) 0x04 // file identifier of the NDEF file retrieved from the CC file
    };

    private static final byte[] NDEF_READ_BINARY_NLEN = {
            (byte) 0x00, // Class byte (CLA)
            (byte) 0xb0, // Instruction byte (INS) for ReadBinary command
            (byte) 0x00, (byte) 0x00, // Parameter byte (P1, P2), offset inside the CC file
            (byte) 0x02  // Le field
    };

    private static final byte[] NDEF_READ_BINARY_GET_NDEF = {
            (byte) 0x00, // Class byte (CLA)
            (byte) 0xb0, // Instruction byte (INS) for ReadBinary command
            (byte) 0x00, (byte) 0x00, // Parameter byte (P1, P2), offset inside the CC file
            (byte) 0x0f  //  Le field
    };

    private static final byte[] A_OKAY = {
            (byte) 0x90,  // SW1	Status byte 1 - Command processing status
            (byte) 0x00   // SW2	Status byte 2 - Command processing qualifier
    };

    private static final byte[] NDEF_ID = {
            (byte) 0xE1,
            (byte) 0x04
    };

    private NdefRecord NDEF_URI = new NdefRecord(
            NdefRecord.TNF_WELL_KNOWN,
            NdefRecord.RTD_TEXT,
            NDEF_ID,
            "Hello world!".getBytes(Charset.forName("UTF-8"))
    );
    String defaultNdefMessage = "NfcHceNdefReaderSender default message from " + Utils.getTimestamp();
    private byte[] NDEF_URI_BYTES = getNdefMessage(defaultNdefMessage);
    private byte[] NDEF_URI_LEN = BigInteger.valueOf(NDEF_URI_BYTES.length).toByteArray();

    private byte[] getNdefMessage(String ndefData) {
        if (ndefData.length() == 0) {
            return new byte[0];
        }
        NdefMessage ndefMessage;
        NdefRecord ndefRecord;
        ndefRecord = NdefRecord.createTextRecord("en", ndefData);
        ndefMessage = new NdefMessage(ndefRecord);
        return ndefMessage.toByteArray();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {

        if (intent.hasExtra("ndefMessage")) {
            Log.i(TAG, "NDEF will be created and CardService runs");

            // here we are using the NDEF message + record to create ndef data
            NDEF_URI_BYTES = getNdefMessage(intent.getStringExtra("ndefMessage"));
            NDEF_URI_LEN = BigInteger.valueOf(NDEF_URI_BYTES.length).toByteArray();

            Context context = getApplicationContext();
            CharSequence text = "Your NDEF text has been set!";
            int duration = Toast.LENGTH_SHORT;
            Toast toast = Toast.makeText(context, text, duration);
            //toast.setGravity(Gravity.CENTER, 0, 0);
            toast.show();
        } else {
        Log.i(TAG, "NDEF text is empty");
        return START_REDELIVER_INTENT;
    }

        Log.i(TAG, "onStartCommand() | NDEF" + NDEF_URI.toString());

        return START_STICKY;
    }

    @Override
    public byte[] processCommandApdu(byte[] commandApdu, Bundle extras) {

        //
        // The following flow is based on Appendix E "Example of Mapping Version 2.0 Command Flow"
        // in the NFC Forum specification
        //
        Log.i(TAG, "processCommandApdu() | incoming commandApdu: " + Utils.bytesToHex(commandApdu));

        //
        // First command: NDEF Tag Application select (Section 5.5.2 in NFC Forum spec)
        //
        if (Utils.isEqual(APDU_SELECT, commandApdu)) {
            Log.i(TAG, "APDU_SELECT triggered. Our Response: " + Utils.bytesToHex(A_OKAY));
            return A_OKAY;
        }

        //
        // Second command: Capability Container select (Section 5.5.3 in NFC Forum spec)
        //
        if (Utils.isEqual(CAPABILITY_CONTAINER, commandApdu)) {
            Log.i(TAG, "CAPABILITY_CONTAINER triggered. Our Response: " + Utils.bytesToHex(A_OKAY));
            return A_OKAY;
        }

        //
        // Third command: ReadBinary data from CC file (Section 5.5.4 in NFC Forum spec)
        //
        if (Utils.isEqual(READ_CAPABILITY_CONTAINER, commandApdu) && !READ_CAPABILITY_CONTAINER_CHECK) {
            Log.i(TAG, "READ_CAPABILITY_CONTAINER triggered. Our Response: " + Utils.bytesToHex(READ_CAPABILITY_CONTAINER_RESPONSE));
            READ_CAPABILITY_CONTAINER_CHECK = true;
            return READ_CAPABILITY_CONTAINER_RESPONSE;
        }

        //
        // Fourth command: NDEF Select command (Section 5.5.5 in NFC Forum spec)
        //
        if (Utils.isEqual(NDEF_SELECT, commandApdu)) {
            Log.i(TAG, "NDEF_SELECT triggered. Our Response: " + Utils.bytesToHex(A_OKAY));
            return A_OKAY;
        }

        //
        // Fifth command:  ReadBinary, read NLEN field
        //
        if (Utils.isEqual(NDEF_READ_BINARY_NLEN, commandApdu)) {

            byte[] start = {
                    (byte) 0x00
            };

            // Build our response
            byte[] response = new byte[start.length + NDEF_URI_LEN.length + A_OKAY.length];

            System.arraycopy(start, 0, response, 0, start.length);
            System.arraycopy(NDEF_URI_LEN, 0, response, start.length, NDEF_URI_LEN.length);
            System.arraycopy(A_OKAY, 0, response, start.length + NDEF_URI_LEN.length, A_OKAY.length);

            Log.i(TAG, "response: " + Utils.bytesToHex(response));
            Log.i(TAG, "NDEF_READ_BINARY_NLEN triggered. Our Response: " + Utils.bytesToHex(response));
            // todo runs up to this point
            return response;
        }

        // processCommandApdu() | incoming commandApdu: 00B0000229
        // todo processCommandApdu() | I don't know what's going on!!!.
        Log.i(TAG, "processCommandApdu() |      incoming commandApdu: " + Utils.bytesToHex(commandApdu));
        Log.i(TAG, "processCommandApdu() | NDEF_READ_BINARY_GET_NDEF: " + Utils.bytesToHex(NDEF_READ_BINARY_GET_NDEF));
/*
I/HostApduService: processCommandApdu() |      incoming commandApdu: 00B0000229
I/HostApduService: processCommandApdu() | NDEF_READ_BINARY_GET_NDEF: 00B000000F
 */
        //
        // Sixth command: ReadBinary, get NDEF data
        //

        // need the data from step 5
        final byte[] NDEF_READ_BINARY_GET_NDEF2 = {
                (byte) 0x00, // Class byte (CLA)
                (byte) 0xb0, // Instruction byte (INS) for ReadBinary command
                (byte) 0x00, (byte) 0x02, // Parameter byte (P1, P2), offset inside the CC file
                (byte) 0x29  //  Le field
        };
        Log.i(TAG, "processCommandApdu() | NDEF_READ_BINARY_GET_NDF2: " + Utils.bytesToHex(NDEF_READ_BINARY_GET_NDEF2));

        //if (Utils.isEqual(NDEF_READ_BINARY_GET_NDEF, commandApdu)) {
        if (Utils.isEqual(NDEF_READ_BINARY_GET_NDEF2, commandApdu)) {
            Log.i(TAG, "processCommandApdu() | NDEF_READ_BINARY_GET_NDEF triggered");

            byte[] start = {
                    (byte) 0x00
            };

            // Build our response
            byte[] response = new byte[start.length + NDEF_URI_LEN.length + NDEF_URI_BYTES.length + A_OKAY.length];

            System.arraycopy(start, 0, response, 0, start.length);
            System.arraycopy(NDEF_URI_LEN, 0, response, start.length, NDEF_URI_LEN.length);
            System.arraycopy(NDEF_URI_BYTES, 0, response, start.length + NDEF_URI_LEN.length, NDEF_URI_BYTES.length);
            System.arraycopy(A_OKAY, 0, response, start.length + NDEF_URI_LEN.length + NDEF_URI_BYTES.length, A_OKAY.length);

            Log.i(TAG, NDEF_URI.toString());
            Log.i(TAG, "NDEF_READ_BINARY_GET_NDEF triggered. Our Response: " + Utils.bytesToHex(response));

/* this is what Kotlin does now:
        if (Arrays.equals(commandApdu.sliceArray(0..1), NDEF_READ_BINARY)) {
            val offset = commandApdu.sliceArray(2..3).toHex().toInt(16)
            val length = commandApdu.sliceArray(4..4).toHex().toInt(16)

            val fullResponse = ByteArray(NDEF_URI_LEN.size + NDEF_URI_BYTES.size)
            System.arraycopy(NDEF_URI_LEN, 0, fullResponse, 0, NDEF_URI_LEN.size)
            System.arraycopy(
                NDEF_URI_BYTES,
                0,
                fullResponse,
                NDEF_URI_LEN.size,
                NDEF_URI_BYTES.size
            )

            Log.i(TAG, "NDEF_READ_BINARY triggered. Full data: " + fullResponse.toHex())
            Log.i(TAG, "READ_BINARY - OFFSET: " + offset + " - LEN: " + length)

            val slicedResponse = fullResponse.sliceArray(offset until fullResponse.size)

            // Build our response
            val realLength = if (slicedResponse.size <= length) slicedResponse.size else length
            val response = ByteArray(realLength + A_OKAY.size)

            System.arraycopy(slicedResponse, 0, response, 0, realLength)
            System.arraycopy(A_OKAY, 0, response, realLength, A_OKAY.size)


 */
/*
NDEF_READ_BINARY triggered. Full data:    002C D901250254E10402656E546875204D61722033302031313A32393A353820474D542B30323A30302032303233
NDEF_READ_BINARY triggered. Our Response:      D901250254E10402656E546875204D61722033302031313A32393A353820474D542B30323A303020323032339000
I/HostApduService: READ_BINARY - OFFSET: 2 - LEN: 44
 */

/*
https://stackoverflow.com/q/56168943/8166854
final static int APDU_P1 = 2;
final static int APDU_P2 = 3;
final static int APDU_READ_LE = 4;
final static byte[] RET_COMPLETE = { (byte)0x90, (byte)0x00 };

int offset = ((commandApdu[APDU_P1]) << 8) | commandApdu[APDU_P2];
..
retData = new byte[commandApdu[APDU_READ_LE] + RET_COMPLETE.length];
//read data
System.arraycopy(src, offset, retData, 0, commandApdu[APDU_READ_LE]);
//complete
System.arraycopy(RET_COMPLETE, 0, retData, commandApdu[APDU_READ_LE], RET_COMPLETE.length);
 */

            final int APDU_P1 = 2;
            final int APDU_P2 = 3;
            final int APDU_READ_LE = 4;
            final byte[] RET_COMPLETE = { (byte)0x90, (byte)0x00 };
            int offset2 = ((commandApdu[APDU_P1]) << 8) | commandApdu[APDU_P2];

            response = new byte[commandApdu[APDU_READ_LE] + RET_COMPLETE.length];
            //read data
            System.arraycopy(NDEF_URI_BYTES, offset2, response, 0, commandApdu[APDU_READ_LE]);
            //complete
            System.arraycopy(RET_COMPLETE, 0, response, commandApdu[APDU_READ_LE], RET_COMPLETE.length);
            Log.i(TAG, "NDEF_READ_BINARY_GET_NDEF triggered. Our Response: " + Utils.bytesToHex(response));

            Context context = getApplicationContext();
            CharSequence text = "NDEF text has been sent to the reader!";
            int duration = Toast.LENGTH_SHORT;
            Toast toast = Toast.makeText(context, text, duration);
            //toast.setGravity(Gravity.CENTER, 0, 0);
            toast.show();

            READ_CAPABILITY_CONTAINER_CHECK = false;
            //return response;

            // https://github.com/TechBooster/C85-Android-4.4-Sample/blob/master/chapter08/NdefCard/src/com/example/ndefcard/NdefHostApduService.java
            int offset = (0x00ff & commandApdu[2]) * 256 + (0x00ff & commandApdu[3]);
            int le = 0x00ff & commandApdu[4];

            // R-APDU用のバッファを生成する
            byte[] responseApdu = new byte[le + RET_COMPLETE.length];

/*
            if (mCcSelected && offset == 0 && le == CC_FILE.length) {
                // CC選択時はオフセットが0、長さがファイル長(15)と一致していなければならない
                System.arraycopy(CC_FILE, offset, responseApdu, 0, le);
                System.arraycopy(SUCCESS_SW, 0, responseApdu, le, SUCCESS_SW.length);

                return responseApdu;

            } else if (mNdefSelected) {
                if (offset + le <= mNdefRecordFile.length) {
                    System.arraycopy(mNdefRecordFile, offset, responseApdu, 0, le);
                    System.arraycopy(SUCCESS_SW, 0, responseApdu, le, SUCCESS_SW.length);

                    return responseApdu;
                }
            }
*/
            if (offset + le <= NDEF_URI_BYTES.length) {
                System.arraycopy(NDEF_URI_BYTES, offset, responseApdu, 0, le);
                System.arraycopy(RET_COMPLETE, 0, responseApdu, le, RET_COMPLETE.length);

                return responseApdu;
            }


        }

        //
        // We're doing something outside our scope
        //
        Log.wtf(TAG, "processCommandApdu() | I don't know what's going on!!!.");
        return "Can I help you?".getBytes();
    }

    @Override
    public void onDeactivated(int reason) {
        Log.i(TAG, "onDeactivated() Fired! Reason: " + reason);
    }
}