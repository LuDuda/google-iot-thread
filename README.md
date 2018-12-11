# Google Cloud IoT - CoAP Example

This repository contains example of Google Cloud IoT interaction with the Thread enabled devices.

Thread is an emerging low-power and constrained-friendly IP based networking protocol with
tremendous potential. This demo shows the power of Thread and the power of Google IoT Core as a point of connectivity for all IoT devices.

[![Logo][logo]][repo]

[logo]: doc/overview.png
[repo]: https://github.com/LuDuda/google-iot-thread

This example is an addition to the nRF5 SDK for Thread and Zigbee released by Nordic Semiconductor.

## Thread network paramers

The Thread device has been pre-commissioned with the following parameters:

| Parameter | Value |
|-----------|-------|
| Network Name | GCP Demo |
| PAN ID | 0xabcd |
| Network Key | 00112233445566778899aabbccddeeff |
| Extended PAN ID | dead00beef00cafe |
| Channel | 11 |
| On-Mesh Prefix | fd11:22:: |

    Make sure that those values are aligned with those set on OpenThread Border Router.

Above default values are configurable from `main.c` file of the example.

## Google IoT Cloud setup

Create a “Device” keypair (see [here](https://cloud.google.com/iot/docs/how-tos/credentials/keys#generating_an_es256_key) for more info):

```bash
openssl ecparam -genkey -name prime256v1 -noout -out ec_private.pem
openssl ec -in ec_private.pem -pubout -out ec_public.pem
```

Go to your IOT Core registry, create a device via the Cloud Console or gcloud.

### via Cloud Console:
Give it a Device ID - it should match whatever is configured in the python script.
Select ES256 Public key format, copy the contents of ec_public.pem.

### via gcloud:
gcloud beta iot devices create SOMEDEVICEID --region us-central1 --project \
coap-iot-proxy --registry test-reg --public-key path=ec_public.pem,type=ES256

## How to build

In order to build the example please follow below instruction:

1. Download nRF5 SDK for Thread and Zigbee v2.0.0 from this [website](https://www.nordicsemi.com/Software-and-Tools/Software/nRF5-SDK-for-Thread-and-Zigbee)
2. Copy content of `thread/examples/google_iot_coap` directory into coresponding folder in the previously downloaded SDK.
3. Unzip `openthread_1253becb.zip` to the `thread/examples/google_iot_coap` directory. Note that you should see following path styrcuture: `thread/examples/google_iot_coap/openthread_1253becb/lib`
4. Change directory to the example's armgcc project.
    ```bash
    cd thread/examples/google_iot_coap/pca10056/armgcc
    ```
5. Make sure to provide correct credentials (Device ID and Private Key) by filling `GCP_COAP_IOT_CORE_DEVICE_ID` and `GCP_COAP_IOT_CORE_DEVICE_KEY` defines
   in the `thread/examples/google_iot_coap/main.c` file.

    For example:
    ```bash
    #define GCP_COAP_IOT_CORE_DEVICE_ID      "nrf52-01"
    #define GCP_COAP_IOT_CORE_DEVICE_KEY   
    "-----BEGIN EC PRIVATE KEY-----\r\n"                                   \
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\r\n" \
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\r\n" \
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX==\r\n"                             \
    "-----END EC PRIVATE KEY-----\r\n"
    ```
6. Build example using make.
    ```bash
    make
    ```
7. Flash firmware to the nRF52840 DK.
    ```bash
    make erase flash
    ```

## Enable end-to-end security (CoAPs)

In order to enable DTLS session between the Thread device and Google IoT Cloud, modify following line in the `main.c` file of the example:

```bash 
#define GCP_COAP_SECURE_ENABLED 0
```

and change it to:

```bash 
#define GCP_COAP_SECURE_ENABLED 1
```

## Interaction with nRF52840 Development Kit 

You can interact with the development kit by using buttons and leds.

1. Open Firestore database and choose your device.
2. Turn on OpenThread Border Router.
3. Turn on Thread Device and wait few seconds to make sure that device joined a Thread Network.
4. Observe LED status:
    - LED1 blinking: Device is joining a Thread Network
    - LED1 solid:    Device joined a Thread Network
5. Push `BUTTON 3` to decrease simulated `counter` value.
6. Observe data received in Firestore database.
   https://console.cloud.google.com/firestore/data/devices/{DEVICE_ID}?project=coap-iot-proxy
7. Push `BUTTON 4` to increase simulated `counter` value.
8. Observe data received in Firestore database.
   https://console.cloud.google.com/firestore/data/devices/{DEVICE_ID}?project=coap-iot-proxy
9. Push `BUTTON 1` to obtain configuration of the device. Note that device accepts only following strings encoded in base64: 
    - LED1
    - LED2
    - LED3
    - LED4
10. Observe that only configured LED is turned on.
