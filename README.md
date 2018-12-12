# Google Cloud IoT - CoAP Example

This repository contains an example of Google Cloud IoT interaction with the Thread-enabled devices over CoAP and CoAPs.

Thread is an emerging low-power and constraint-friendly IP-based networking protocol with
tremendous potential. This demo shows the potential of Thread and the potential of Google IoT Core as a point of connectivity for all IoT devices.

[![Logo][logo]][repo]

[logo]: doc/overview.png
[repo]: https://github.com/LuDuda/google-iot-thread

This example is an addition to the [nRF5 SDK for Thread and Zigbee v2.0.0]((https://www.nordicsemi.com/Software-and-Tools/Software/nRF5-SDK-for-Thread-and-Zigbee)) released by Nordic Semiconductor.

Additionally, the new set of updated OpenThread libraries has been generated from the following [commit](https://github.com/openthread/openthread/commit/1253becb720e0d8afc1cb0f1e39a76225a235e77). Since the latest SDK does not include new OpenThread features, such as SNTP client or CoAP extensions, this example uses new libraries archived in the `openthread_1253becb.zip` file.

## Thread network parameters

The firmware precommissions a Thread device with the following parameters:

| Parameter | Value |
|-----------|-------|
| Network Name | GCP Demo |
| PAN ID | 0xabcd |
| Network Key | 00112233445566778899aabbccddeeff |
| Extended PAN ID | dead00beef00cafe |
| Channel | 11 |
| On-Mesh Prefix | fd11:22:: |

The above default values are configurable from the `main.c` file of the example.

## Google IoT Cloud setup

In order for a device to connect, it must first be registered with Cloud IoT Core. Registration consists of adding a device to a collection (the registry) and defining some essential properties. You can register a device with Cloud Platform Console or gcloud commands.

Cloud IoT Core uses public key (or asymmetric) authentication:

 - The device uses a private key to sign a JSON Web Token (JWT). The token is passed to Cloud IoT Core as proof of the device's identity.
 - The service uses the device public key (uploaded before the JWT is sent) to verify the device's identity.
For details, see the sections on [creating key pairs](https://cloud.google.com/iot/docs/how-tos/credentials/keys), [using JWTs](https://cloud.google.com/iot/docs/how-tos/credentials/jwts), and [device security](https://cloud.google.com/iot/docs/concepts/device-security).

The first step to activate a new device is to create a “Device” keypair (see [here](https://cloud.google.com/iot/docs/how-tos/credentials/keys#generating_an_es256_key) for more info):

To generate an ES256 key pair using the Eliptic Curve algorithm, run the following commands:

```bash
openssl ecparam -genkey -name prime256v1 -noout -out ec_private.pem
openssl ec -in ec_private.pem -pubout -out ec_public.pem
```

These commands create the following public/private key pair:

 - **ec_private.pem**: The private key that must be securely stored on the device. It is used to sign the authentication JWT.
 - **ec_public.pem**: The public key that must be stored in Cloud IoT Core. It is used to verify the signature of the authentication JWT.

Next, go to your IOT Core registry, create a device via the Cloud Console or gcloud.

### via Cloud Console:
Provide a Device ID - it should match whatever is configured in the `main.c` file of the example (as `GCP_COAP_IOT_CORE_DEVICE_ID`). Select ES256 Public key format and copy the contents of ec_public.pem.

### via gcloud:

Run the following commands:

```bash
gcloud beta iot devices create SOMEDEVICEID --region us-central1 --project \
coap-iot-proxy --registry test-reg --public-key path=ec_public.pem,type=ES256
```

## Thread Border Router

A Thread Border Router connects a Thread network to other IP-based networks, such as Wi-Fi or Ethernet. A Thread network uses Border Router to connect to other networks. This example uses IPv4 connectivity with Google IoT Cloud and therefore it is required in this demo.

Follow [OpenThread Border Router guide](https://openthread.io/guides/border-router) in order to set up Raspberry Pi 3B with Nordic nRF52840 acting as NCP. 

Make sure that Thread network parameters at OpenThread Border Router are aligned with those set in [firmware side](#Thread-network-parameters).

## Environment setup for firmware

You must install a set of tools to complete the environment setup process. Because this repository contains a plugin of the regular nRF5 SDK for Thread and Zigbee, follow the [Environment setup section](https://www.nordicsemi.com/en/DocLib/Content/SDK_Doc/Thread_SDK/v2-0-0/thread_intro?4#thread_qsg_env_setup).

## How to build

Follow these instructions to build firmware for the nRF52840 device.

1. Download nRF5 SDK for Thread and Zigbee v2.0.0 from this [website](https://www.nordicsemi.com/Software-and-Tools/Software/nRF5-SDK-for-Thread-and-Zigbee)
2. Copy the content of the `thread/examples/google_iot_coap` directory into a coresponding folder in the previously downloaded SDK.
3. Unzip `openthread_1253becb.zip` to the `thread/examples/google_iot_coap` directory. Note that you should see the following path structure: `thread/examples/google_iot_coap/openthread_1253becb/lib`
4. Change the directory to the example's armgcc project.
    ```bash
    cd thread/examples/google_iot_coap/pca10056/armgcc
    ```
5. Make sure to provide correct credentials (*Device ID* and *Private Key*) by filling `GCP_COAP_IOT_CORE_DEVICE_ID` and `GCP_COAP_IOT_CORE_DEVICE_KEY` defines in the `thread/examples/google_iot_coap/main.c` file.

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
6. Build the example.
    ```bash
    make
    ```
7. Flash the firmware to the nRF52840 DK.
    ```bash
    make erase flash
    ```

## Enable end-to-end security (CoAPs)

In order to enable a DTLS session between the Thread device and Google IoT Cloud, modify the following line in the `main.c` file of the example:

```bash 
#define GCP_COAP_SECURE_ENABLED 0
```

and change it to:

```bash 
#define GCP_COAP_SECURE_ENABLED 1
```

## Interaction with nRF52840 Development Kit 

You can interact with the development kit by using buttons and LEDs.

1. Open [Firestore database](https://console.cloud.google.com/firestore?project=coap-iot-proxy) and choose your device.
2. Turn on OpenThread Border Router.
3. Turn on the Thread Device and wait few seconds to make sure that device joined a Thread Network.
4. Observe LED status:
    - LED1 blinking: Device is joining a Thread Network
    - LED1 solid:    Device joined a Thread Network
5. Push `BUTTON 3` to decrease the simulated `counter` value.
6. Observe data received in Firestore database.
   https://console.cloud.google.com/firestore/data/devices/{DEVICE_ID}?project=coap-iot-proxy
7. Push `BUTTON 4` to increase the simulated `counter` value.
8. Observe data received in Firestore database.
   https://console.cloud.google.com/firestore/data/devices/{DEVICE_ID}?project=coap-iot-proxy
9. Push `BUTTON 1` to obtain configuration of the device. Note that the device accepts only the following strings encoded in base64: 
    - LED1
    - LED2
    - LED3
    - LED4
10. Observe that only the configured LED is turned on.

## Troubleshooting

### How to verify Thread Border Router has been booted up correctly and provide Internet access?

Follow [this guide](https://openthread.io/guides/border-router/docker/test-connectivity) to test connectivity to public Google DNS server (64:ff9b::808:808) and Google Cloud IoT CoAP Proxy (64:ff9b::23c1:f84c).

### How to verify that two nodes have joined the same network and my device communicates with Google IoT Cloud?

You can use the [IEEE 802.15.4 sniffer](https://github.com/NordicPlayground/nRF-802.15.4-sniffer) project to sniff Thread packets. To decrypt them correctly, you need to set up Wireshark according to the points from 4 to 8 in the following [guide](https://www.nordicsemi.com/en/DocLib/Content/SDK_Doc/Thread_SDK/v2-0-0/thread_sniffer?68#thread_sniffer_starting).

