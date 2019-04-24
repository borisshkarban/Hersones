/////////////kernel libraries//////////
#include <ti/drivers/pin/PINCC26XX.h>
//#include <ti/display/Display.h>
#include <ti/sysbios/knl/Semaphore.h>
#include "Board.h"
#include <ti/sysbios/knl/Clock.h>
#include <ti/sysbios/BIOS.h>
#include <ti/sysbios/knl/Task.h>

////////LIBRARIES////////////////////
#include <stdlib.h>

/////////////TI Drivers/////////////////
#include <ti/drivers/rf/RF.h>
#include <ti/drivers/PIN.h>
#include <ti/drivers/pin/PINCC26XX.h>
#include <GPIOconf.h>


#include <ti/drivers/SPI.h>

/////////// Display////////////////////
#include <ti/display/Display.h>

///////////Board Header files //////////////
#include "Board.h"

///////// Application Header files//////////////
#include "RFQueue.h"
#include "smartrf_settings/smartrf_settings.h"

#include <ti/devices/DeviceFamily.h>
#include DeviceFamily_constructPath(driverlib/rf_prop_mailbox.h)

#define COMMAND_START   0xCC
#define COMMAND_STOP    0x33
#define COMMAND_CONFIRM_START 0x34
#define COMMAND_CONFIRM_STOP  0x35
#define COMMAND_NOCONFIRM  0x36
#define COMMAND_NOANSWER 0x55

#define ADDRESS         0x120a05

#define IDLE_STATE       0
#define STATUS_SND      1
#define ANSWER_WAIT     2
#define CONFIRM_BACK     3
/////////////////DEFINITIONS/////////////////////////////
/////////// Wake-on-Radio wakeups per second */
#define WOR_WAKEUPS_PER_SECOND 2

// Wake-on-Radio mode. Can be:
 // - RSSI only
 //- PQT, preamble detection
 // - Both, first RSSI and then PQT if RSSI  */
#define WOR_MODE CarrierSenseMode_RSSIandPQT

////Threshold for RSSI based Carrier Sense in dBm //////
#define WOR_RSSI_THRESHOLD      ((int8_t)(-111))

/// Macro used to set actual wakeup interval////////
#define WOR_WAKE_UP_MARGIN_S 0.005f
#define WOR_WAKE_UP_INTERVAL_RAT_TICKS(x) \
    ((uint32_t)(4000000*(1.0f/(x) - (WOR_WAKE_UP_MARGIN_S))))

#define PAYLOAD_LENGTH         8
/////////Set Transmit (echo) delay to 100ms /////////////
//#define TX_DELAY             (uint32_t)(4000000*0.1f)
#define TX_DELAY             (uint32_t)(4000000*0.05f)
////Packet Configuration
#define DATA_ENTRY_HEADER_SIZE 8  //// Constant header size of a Generic Data Entry
#define MAX_LENGTH             31 //// Max length byte the radio will accept
#define NUM_DATA_ENTRIES       2  //// NOTE: Only two data entries supported at the moment
#define NUM_APPENDED_BYTES     1  //// Length byte included in the stored packet

//////TYPES/////////////////////////////
//General wake-on-radio RX statistics//
struct WorStatistics {
  uint32_t doneIdle;
  uint32_t doneIdleTimeout;
  uint32_t doneRxTimeout;
  uint32_t doneOk;
};

///Modes of carrier sense possible //
enum CarrierSenseMode {
    CarrierSenseMode_RSSI,
    CarrierSenseMode_PQT,
    CarrierSenseMode_RSSIandPQT,
};

//////////////VARIABLES//////////////////////////////////////
/// RF driver object and handle /////////////////////////////
static RF_Object rfObject;  //////////////// RF_open instance
static RF_Handle rfHandle;////////////////// Handle to RF instance

extern int state;
///****///uint8_t Rx_Rcv_packet[PAYLOAD_LENGTH];

/// General wake-on-radio sniff status statistics and statistics from the RF Core about received packets///////////
static volatile struct WorStatistics worStatistics;
static rfc_propRxOutput_t rxStatistics;


/// Buffer which contains all Data Entries for receiving data./////////////////////////////////////
/// Pragmas are needed to make sure this buffer is 4 byte aligned (requirement from the RF Core)///
#pragma DATA_ALIGN (rxDataEntryBuffer, 4);
static uint8_t rxDataEntryBuffer[RF_QUEUE_DATA_ENTRY_BUFFER_SIZE(NUM_DATA_ENTRIES,MAX_LENGTH,NUM_APPENDED_BYTES)];

/// RX Data Queue and Data Entry pointer to read out received packets ///
static dataQueue_t dataQueue;
static rfc_dataEntryGeneral_t* currentDataEntry;

/// Received packet's length and pointer to the payload///
static uint8_t packetLength;
///****/////static uint8_t* packetDataPointer;
uint16_t StatusWord;
uint8_t* packetDataPointer;

static volatile uint8_t dummy;

///received by Rx packet is here/////
extern uint8_t  *rcv_buffer;
volatile char cmd;

static uint8_t txPacket[PAYLOAD_LENGTH];

#ifdef LOG_RADIO_EVENTS
static volatile RF_EventMask eventLog[32];
static volatile uint8_t evIndex = 0;
#endif // LOG_RADIO_EVENTS

////Sniff command for doing combined Carrier Sense and RX/////////////
static rfc_CMD_PROP_RX_SNIFF_t RF_cmdPropRxSniff;

/////////Prototypes and Callback functions///////////////////////////////
/////--static void callback(RF_Handle h, RF_CmdHandle ch, RF_EventMask e);
static void initializeSniffCmdFromRxCmd(rfc_CMD_PROP_RX_SNIFF_t* rxSniffCmd, rfc_CMD_PROP_RX_t* rxCmd);
static void configureSniffCmd(rfc_CMD_PROP_RX_SNIFF_t* rxSniffCmd, enum CarrierSenseMode mode, uint32_t datarate, uint8_t wakeupPerSecond);
static uint32_t calculateSymbolRate(uint8_t prescaler, uint32_t rateWord);
static void echoCallback(RF_Handle h, RF_CmdHandle ch, RF_EventMask e);

///////////////////main radio task - sniffering commands in yje air/////////////////////////////////////////////
void RadioSnifferRxTaskFxn(UArg a0, UArg a1)
{
    RF_Params rfParams;
    RF_Params_init(&rfParams);


    ///////////// Create QUEUE and data entries/////////////////////////////////////////
    if (RFQueue_defineQueue(&dataQueue,rxDataEntryBuffer, sizeof(rxDataEntryBuffer), NUM_DATA_ENTRIES, MAX_LENGTH + NUM_APPENDED_BYTES))
    {
        while(1);
    }
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////Forming RF_cmdPropRxSniff command which is the main command for Radio receiving///////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    ///////Just Copy all RX options from the SmartRF Studio exported RX command (CMD_PROP_RX #3802 with preestablished constant values) to the RX Sniff command(#3808)////////
    initializeSniffCmdFromRxCmd(&RF_cmdPropRxSniff, &RF_cmdPropRx);

    ////Configure RX part of RX_SNIFF command///////////////////
    RF_cmdPropRxSniff.pQueue    = &dataQueue;

    RF_cmdPropRxSniff.pOutput   = (uint8_t*)&rxStatistics;
    RF_cmdPropRxSniff.maxPktLen = MAX_LENGTH;

    RF_cmdPropRxSniff.pktConf.bRepeatOk = 0;
    RF_cmdPropRxSniff.pktConf.bRepeatNok = 1;
    RF_cmdPropRxSniff.startTrigger.triggerType = TRIG_NOW;
    RF_cmdPropRxSniff.pNextOp = (rfc_radioOp_t *)&RF_cmdPropTx;
    ///Only run the TX command if RX is successful///
    RF_cmdPropRxSniff.condition.rule =COND_STOP_ON_FALSE;

    //////// Discard ignored packets and CRC errors from Rx queue ///////////////////
    RF_cmdPropRxSniff.rxConf.bAutoFlushIgnored = 1;
    RF_cmdPropRxSniff.rxConf.bAutoFlushCrcErr  = 1;

    ////////////////////configure Tx command just after (100 ms) Rx
    RF_cmdPropTx.pktLen = PAYLOAD_LENGTH;

    RF_cmdPropTx.pPkt = txPacket;
    RF_cmdPropTx.startTrigger.triggerType = TRIG_REL_PREVEND;
    RF_cmdPropTx.startTime = TX_DELAY;

    ///// DataRate calculation from prescaler and rate word /////////////////////////////////////////////////////////////////////////
    uint32_t datarate = calculateSymbolRate(RF_cmdPropRadioDivSetup.symbolRate.preScale,RF_cmdPropRadioDivSetup.symbolRate.rateWord);

    ///// Configure Sniff-mode part of the RX_SNIFF command /////////////////////////////////////////////////////////////////////////
    configureSniffCmd(&RF_cmdPropRxSniff, WOR_MODE, datarate, WOR_WAKEUPS_PER_SECOND);

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////SETTING UP RADIO////////////////////////////////////////////////////////////////////////////////////////////
    ////// Request access to the radio with &RF_cmdPropRadioDivSetup (with preestablished constant values)//////////////////////////////
    rfHandle = RF_open(&rfObject, &RF_prop, (RF_RadioSetup*)&RF_cmdPropRadioDivSetup, &rfParams);

    //////////Set frequency just standard command RF_cmdFs the same as for transceiving program////////////////////////////////
    RF_runCmd(rfHandle, (RF_Op*)&RF_cmdFs, RF_PriorityNormal, NULL, 0);
    //////////Save the current radio time/////////////////////
    RF_cmdPropRxSniff.startTime = RF_getCurrentTime();

    StatusWord=0x8080;

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    //////////The WHILE LOOP///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    while(1)
    {
        /////////////////// Set next wakeup time FOR RF_cmdPropRxSniff COMMAND (Here 0.5 sec) /////////////////////////////
        RF_cmdPropRxSniff.startTime += WOR_WAKE_UP_INTERVAL_RAT_TICKS(WOR_WAKEUPS_PER_SECOND);

        RF_EventMask terminationReason = RF_runCmd(rfHandle, (RF_Op*)&RF_cmdPropRxSniff, RF_PriorityNormal,echoCallback, (RF_EventRxEntryDone |RF_EventLastCmdDone));

        uint32_t cmdStatus = ((volatile RF_Op*)&RF_cmdPropRxSniff)->status;
        switch(cmdStatus)
        {
           case PROP_DONE_OK:
               // Packet received with CRC OK
               /////////if address coincides///////////////////////////////
               if((!(*(packetDataPointer+2)^((ADDRESS>>16)&0x0000ff))&&(!(*(packetDataPointer+3)^((ADDRESS>>8)&0x0000ff)))&&(!(*(packetDataPointer+4)^((ADDRESS)&0x0000ff))))&&(state==IDLE_STATE))
               {
                   ////////////setting change(iterrupt bit)////////////
                   StatusWord&=0xBFFF;StatusWord^=0x4000;
                   /////////setting start bit////////////////////////
                   if (*(packetDataPointer+5)==COMMAND_START) {StatusWord&=0xFFBF;StatusWord^=0x0040;}
                   ///////////////setting stop bit////////////////////////
                   else if (*(packetDataPointer+5)==COMMAND_STOP) {StatusWord&=0xFFBF;StatusWord^=0x0000;}

                }
               else {StatusWord=0x00;GPIO_write(GPIOintPIN_rfInt, 0);}

//               cmd='t';

           break;
           case PROP_DONE_RXERR: break;
           case PROP_DONE_RXTIMEOUT:break;
           case PROP_DONE_BREAK: break;
           case PROP_DONE_ENDED: break;
           case PROP_DONE_STOPPED:break;
           case PROP_DONE_ABORT:break;
           case PROP_ERROR_RXBUF:break;
           case PROP_ERROR_RXFULL:break;
           case PROP_ERROR_PAR:break;
           case PROP_ERROR_NO_SETUP:break;
           case PROP_ERROR_NO_FS:break;
           case PROP_ERROR_RXOVF:break;
           default:  break;
           }
    }
}

////// Calculates datarate from prescaler and rate word////////////////
static uint32_t calculateSymbolRate(uint8_t prescaler, uint32_t rateWord)
{
    /* Calculate datarate according to TRM Section 23.7.5.2:
     * f_baudrate = (R * f_ref)/(p * 2^20)
     *   - R = rateWord
     *   - f_ref = 24Mhz
     *   - p = prescaler */
    uint64_t numerator = rateWord*24000000ULL;
    uint64_t denominator = prescaler*1048576ULL;
    uint32_t result = (uint32_t)(numerator/denominator);
    return result;
}

//////Just Copying all RX options from the SmartRF Studio exported RX command to the RX Sniff command */
static void initializeSniffCmdFromRxCmd(rfc_CMD_PROP_RX_SNIFF_t* rxSniffCmd, rfc_CMD_PROP_RX_t* rxCmd)
{

    /* Copy RX configuration from RX command */
    memcpy(rxSniffCmd, rxCmd, sizeof(rfc_CMD_PROP_RX_t));

    /* Change to RX_SNIFF command from RX command */
    rxSniffCmd->commandNo = CMD_PROP_RX_SNIFF;
}

////////// Configures the RX_SNIFF command based on mode, datarate and wakeup interval ////////
static void configureSniffCmd(rfc_CMD_PROP_RX_SNIFF_t* rxSniffCmd, enum CarrierSenseMode mode, uint32_t datarate, uint8_t wakeupPerSecond)
{
    /* Enable or disable RSSI */
    if ((mode == CarrierSenseMode_RSSI) || (mode == CarrierSenseMode_RSSIandPQT)) {
        rxSniffCmd->csConf.bEnaRssi        = 1;
    } else {
        rxSniffCmd->csConf.bEnaRssi        = 0;
    }

    /* Enable or disable PQT */
    if ((mode == CarrierSenseMode_PQT) || (mode == CarrierSenseMode_RSSIandPQT)) {
        rxSniffCmd->csConf.bEnaCorr        = 1;
        rxSniffCmd->csEndTrigger.triggerType  = TRIG_REL_START;
    } else {
        rxSniffCmd->csConf.bEnaCorr        = 0;
        rxSniffCmd->csEndTrigger.triggerType  = TRIG_NEVER;
    }

    /* General Carrier Sense configuration */
    rxSniffCmd->csConf.operation       = 1; /* Report Idle if RSSI reports Idle to quickly exit if not above
                                                 RSSI threshold */
    rxSniffCmd->csConf.busyOp          = 0; /* End carrier sense on channel Busy (the receiver will continue when
                                                 carrier sense ends, but it will then not end if channel goes Idle) */
    rxSniffCmd->csConf.idleOp          = 1; /* End on channel Idle */
    rxSniffCmd->csConf.timeoutRes      = 1; /* If the channel is invalid, it will return PROP_DONE_IDLE_TIMEOUT */

    /* RSSI configuration */
    rxSniffCmd->numRssiIdle            = 1; /* One idle RSSI samples signals that the channel is idle */
    rxSniffCmd->numRssiBusy            = 1; /* One busy RSSI samples signals that the channel is busy */
    rxSniffCmd->rssiThr    = (int8_t)WOR_RSSI_THRESHOLD; /* Set the RSSI threshold in dBm */

    /* PQT configuration */
    rxSniffCmd->corrConfig.numCorrBusy = 1;   /* One busy PQT samples signals that the channel is busy */
    rxSniffCmd->corrConfig.numCorrInv  = 1;   /* One busy PQT samples signals that the channel is busy */

    /* Calculate basic timing parameters */
    uint32_t symbolLengthUs  = 1000000UL/datarate;
    uint32_t preambleSymbols = (1000000UL/wakeupPerSecond)/symbolLengthUs;
    uint8_t syncWordSymbols  = RF_cmdPropRadioDivSetup.formatConf.nSwBits;

    /* Calculate sniff mode parameters */
    #define US_TO_RAT_TICKS 4
    #define CORR_PERIOD_SYM_MARGIN 16
    #define RX_END_TIME_SYM_MARGIN 8
    #define CS_END_TIME_MIN_TIME_SYM 30
    #define CS_END_TIME_MIN_TIME_STATIC_US 150

    /* Represents the time in which we need to receive corrConfig.numCorr* correlation peaks to detect preamble.
     * When continously checking the preamble quality, this period has to be wide enough to also contain the sync
     * word, with a margin. If it is not, then there is a chance the SNIFF command will abort while receiving the
     * sync word, as it no longer detects a preamble. */
    uint32_t correlationPeriodUs = (syncWordSymbols + CORR_PERIOD_SYM_MARGIN)*symbolLengthUs;

    /* Represents the time where we will force a check if preamble is present (only done once).
     * The main idea is that his should be shorter than "correlationPeriodUs" so that if we get RSSI valid, but
     * there is not a valid preamble on the air, we will leave RX as quickly as possible. */
    uint32_t csEndTimeUs = (CS_END_TIME_MIN_TIME_SYM*symbolLengthUs + CS_END_TIME_MIN_TIME_STATIC_US);

    /* Represents the maximum time from the startTrigger to when we expect a sync word to be received. */
    uint32_t rxEndTimeUs = (preambleSymbols + syncWordSymbols + RX_END_TIME_SYM_MARGIN)*symbolLengthUs;

    /* Set sniff mode timing configuration in sniff command in RAT ticks */
    rxSniffCmd->corrPeriod = (uint16_t)(correlationPeriodUs * US_TO_RAT_TICKS);
    rxSniffCmd->csEndTime  = (uint32_t)(csEndTimeUs * US_TO_RAT_TICKS);
    rxSniffCmd->endTime    = (uint32_t)(rxEndTimeUs * US_TO_RAT_TICKS);

    /* Set correct trigger types */
    rxSniffCmd->endTrigger.triggerType   = TRIG_REL_START;
    rxSniffCmd->startTrigger.triggerType = TRIG_ABSTIME;
    rxSniffCmd->startTrigger.pastTrig    = 1;
}


static void echoCallback(RF_Handle h, RF_CmdHandle ch, RF_EventMask e)
{
#ifdef LOG_RADIO_EVENTS
    eventLog[evIndex++ & 0x1F] = e;
#endif// LOG_RADIO_EVENTS

    if (e & RF_EventRxEntryDone)
    {
        cmd='t';
        /////////// Get current unhandled data entry///////////////////////////////
        currentDataEntry = RFQueue_getDataEntry();

        ////Handling a packet, located at &currentDataEntry->data: - Length is the first byte with the current configuration
        packetLength      = *(uint8_t *)(&(currentDataEntry->data));
        packetDataPointer = (uint8_t *)(&(currentDataEntry->data) + 1);

///////////////////////here we forming a packet pointed to by packetDataPointer to send it back///////////////////////
         //// Copy the payload + status byte to the txPacket variable to send back
        memcpy(txPacket, packetDataPointer, packetLength);
        //////////if address is wrong changing to Noanswer 5-th byte////////
        if(!(!(*(packetDataPointer+2)^((ADDRESS>>16)&0x0000ff))&&(!(*(packetDataPointer+3)^((ADDRESS>>8)&0x0000ff)))&&(!(*(packetDataPointer+4)^((ADDRESS)&0x0000ff))))) *(txPacket+5)=COMMAND_NOANSWER;
        else
        {
            if((*(rcv_buffer+3)==0x01) && (*(txPacket+5)==COMMAND_CONFIRM_START)) *(txPacket+5)=COMMAND_CONFIRM_START;
            else if ((*(rcv_buffer+3)==0x01) && (*(txPacket+5)==COMMAND_CONFIRM_STOP)) *(txPacket+5)=COMMAND_NOCONFIRM;
            else if ((*(rcv_buffer+3)==0x00) && (*(txPacket+5)==COMMAND_CONFIRM_STOP)) *(txPacket+5)=COMMAND_CONFIRM_STOP;
            else if ((*(rcv_buffer+3)==0x00) && (*(txPacket+5)==COMMAND_CONFIRM_START)) *(txPacket+5)=COMMAND_NOCONFIRM;
        }

        GPIO_write(GPIOintPIN_rfInt, 1);

        RFQueue_nextEntry();
    }
    else // error
    {
        /// Error Condition: set LED1, clear LED2
    }
}
