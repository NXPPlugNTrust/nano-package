# NXP Application Code Hub
[<img src="https://mcuxpresso.nxp.com/static/icon/nxp-logo-color.svg" width="100"/>](https://www.nxp.com)

#	 	Integrating EdgeLock® SE05X to FRDM-MCX-A development boards


This demo project provides a detailed information on how to integrate the EdgeLock® SE05X Secure Element family and EdgeLock® A5000 into the FRDM development boards of MCX-A family. 
Additionally, the project contains several demo applications to showcase how to enable security on the MCX family. 

A ***Secure Element (SE)*** and ***Secure Authenticator (SA)*** are discrete companion chips which can be connected to any MPU or MCU.  
It has its own powerful core that can perform advanced cryptographic functionalities and protocols.
Both chips are resistant to advanced hardware and software attacks and can be certified with the highest security level. 
Applications which may require a secure element are data-sensitive and critical applications which involve payments, personal information, 
access control systems, government communications and many more. 
NXPs EdgeLock Secure Elements come with broad crypto functionality, and are certified and easy to scale across architectures.

![](./images/SE050_A5000_chip.png) 

### Connecting an external Secure Element or Secure Authenticator to an existing system

A SE and SA can be easily connected to any system, as the requirements are minimal- only power and two pins for I2C are required. 
A SE/SA can share I2C bus with other ICs, and an I2C bus can be SW emulated using 2 GPIOs. 
Additionally, it is easy to integrate thanks to the support of the Plug&Trust Middleware for the software on the host.

<p align="center">
	<img src="./images/ConnectedBoards-MCX-A.png">
</p>

Any platform can connect to the secure element due to minimal requirements
> Hardware integration: 
> -	Only power and two pins for I2C are required
> - Secure element can share I2C bus with other ICs
> - I2C bus can be SW emulated using 2 GPIOs

> Software integration: <br>
> - Plug and Trust nano library offers in addition to the NXP Crypto API as well a **Mbed TLS ALT** implementation for MCU and MPU usage.
> - The full Plug & Trust Middleware ([Link](https://www.nxp.com/webapp/Download?colCode=SE05x-PLUG-TRUST-MW&appType=license)) offers beside Mbed TLS ALT as well:
>   - **PKCS11** module
>   - **OpenSSL engine** and **OpenSSL provider**
>   - PSA Crypto
>   - TPM TSS stack
>   - Android Keymaster


<br>

![](./images/ConnectSEtoHost.png)


<br>

#### Boards: [FRDM-MCXA153](https://www.nxp.com/design/design-center/development-boards-and-designs/general-purpose-mcus/frdm-development-board-for-mcx-a14x-a15x-mcus:FRDM-MCXA153)

#### Expansion Boards: [OM-A5000ARD](https://www.nxp.com/products/security-and-authentication/authentication/development-board-for-edgelock-a5000-secure-authenticator:OM-A5000ARD), [OM-SE050ARD-E](https://www.nxp.com/products/security-and-authentication/authentication/edgelock-se050-development-kits:OM-SE050X), [OM-SE051ARD](https://www.nxp.com/products/security-and-authentication/authentication/edgelock-se051-development-kit:OM-SE051ARD)
#### Categories: Industrial, Secure Provisioning, Security, Cloud Connected Devices	
#### Peripherals: I2C
#### Toolchains: MCUXpresso IDE

## Table of Contents
1. [Software](#step1)
2. [Hardware](#step2)
3. [Setup](#step3)
4. [Results](#step4)
5. [FAQs](#step5) 
6. [Support](#step6)
7. [Release Notes](#step7)

Below the steps necessary to run the nano lib cryptography example on FRDM-MCXA153 are listed.

## 1. Software<a name="step1"></a>
- Install latest MCUxpresso from https://nxp.com/mcuxpresso.
- Download mcxa153 SDK **version 2.16.100** from https://mcuxpresso.nxp.com/en/select. 
- Download the latest Plug & Trust Se05x nano library from https://github.com/NXPPlugNTrust/nano-package/



## 2. Hardware<a name="step2"></a>
You need either one of these SE/SA ARD development kits:
- [OM-A5000ARD](https://www.nxp.com/products/security-and-authentication/authentication/development-board-for-edgelock-a5000-secure-authenticator:OM-A5000ARD)
- [OM-SE050ARD-E](https://www.nxp.com/products/security-and-authentication/authentication/edgelock-se050-development-kits:OM-SE050X)
- [OM-SE051ARD](https://www.nxp.com/products/security-and-authentication/authentication/edgelock-se051-development-kit:OM-SE051ARD)


And a MCU baseboard, here we use:
- [FRDM-MCXA153](https://www.nxp.com/design/design-center/development-boards-and-designs/general-purpose-mcus/frdm-development-board-for-mcx-a14x-a15x-mcus:FRDM-MCXA153)

Place one of the ARD devkits on the MCU baseboard. The jumpers of the ARD devkit can stay in their default position as listed in [OM-SE05xARD Hardware Overview](https://www.nxp.com/webapp/Download?colCode=AN13539)
![SE050E on top ov MCX-A153](./images/ConnectedBoards-MCXA_top.jpg)


## 3. Setup<a name="step3"></a>


### 3.1 Prepare Files
Unzip and place the MCX SDK in parallel to the nano package as shown in the image below. Rename the MCX SDK folder to "mcxa153-sdk":

![](./images/mcxasdk.png)

### 3.2 Import Project

1. Click on File, Import, Existing project to workspace and click on next.

2. Point to the "simw-nanopkg/examples/se05x_crypto/mcxa153" folder. This selects the "crypto" example. The "examples" folder contain other selectable examples as well. For MCX-A these examples are selectable:
   - se05x_GetInfo
   - se05x_crypto
   - se05x_sign

3. Select the Project and click on Finish
![](./images/mcxa_import.png)

### 3.3 Build options 

No build options, currently only build without Platform SCP and EC Key authentication is supported.

### 3.4 Build and Debug

Click on Build and then Debug on the Quickstart panel to Build and Debug your project


## 4. Results<a name="step4"></a>
Executing the example results in output like this, showing the operations done with the secure element:

	Se05x crypto Example !
	Plug and Trust nano package - version: 1.3.0 
	Get Version ==> 
	Applet Version 7.2.0 
	ex_get_version, PASSED 
	ex_generate_nist256_key, PASSED 
	ex_set_get_nist256_key, PASSED 
	ex_nist256_sign_verify, PASSED 
	ex_set_certificate, PASSED 
	ex_ecdh, PASSED 
	ex_aes_ECB_NOPAD, PASSED 
	ex_aes_CBC_NOPAD, PASSED 
	ex_aes_CTR, PASSED 
	ex_nist256_sign_policy, PASSED 
	Close i2c device 3.
	SE05x crypto Example Success ! 


## 5. FAQs<a name="step5"></a>

### Are any changes needed for the different ARD boards?

No, the functions used by the Plug & Trust nano library are the same on these boards:
- [OM-A5000ARD](https://www.nxp.com/products/security-and-authentication/authentication/development-board-for-edgelock-a5000-secure-authenticator:OM-A5000ARD)
- [OM-SE050ARD-E](https://www.nxp.com/products/security-and-authentication/authentication/edgelock-se050-development-kits:OM-SE050X)
- [OM-SE051ARD](https://www.nxp.com/products/security-and-authentication/authentication/edgelock-se051-development-kit:OM-SE051ARD)

### How can other examples be executed?

The example gets selected in the import step. Create another project and import the wanted example from the "examples" folder. Each example has the project file for the supported platforms in a subfolder "example/platform".

## 6. Support<a name="step6"></a>
NXP support community for IoT secure elements: [Community Secure Authentication](https://community.nxp.com/t5/Secure-Authentication/bd-p/secure-authentication)

#### Project Metadata

<!----- Boards ----->
[![Board badge](https://img.shields.io/badge/Board-FRDM&ndash;MCXA153-blue)]()

<!----- Categories ----->
[![Category badge](https://img.shields.io/badge/Category-INDUSTRIAL-yellowgreen)](https://github.com/search?q=org%3Anxp-appcodehub+industrial+in%3Areadme&type=Repositories)
[![Category badge](https://img.shields.io/badge/Category-SECURE%20PROVISIONING-yellowgreen)](https://github.com/search?q=org%3Anxp-appcodehub+sec_provi+in%3Areadme&type=Repositories)
[![Category badge](https://img.shields.io/badge/Category-SECURITY-yellowgreen)](https://github.com/search?q=org%3Anxp-appcodehub+security+in%3Areadme&type=Repositories)

<!----- Peripherals ----->
[![Peripheral badge](https://img.shields.io/badge/Peripheral-I2C-yellow)](https://github.com/search?q=org%3Anxp-appcodehub+i2c+in%3Areadme&type=Repositories)

<!----- Toolchains ----->
[![Toolchain badge](https://img.shields.io/badge/Toolchain-MCUXPRESSO%20IDE-orange)](https://github.com/search?q=org%3Anxp-appcodehub+mcux+in%3Areadme&type=Repositories)

Questions regarding the content/correctness of this example can be entered as Issues within this GitHub repository.

>**Warning**: For more general technical questions regarding NXP Microcontrollers and the difference in expected functionality, enter your questions on the [NXP Community Forum](https://community.nxp.com/)

[![Follow us on Youtube](https://img.shields.io/badge/Youtube-Follow%20us%20on%20Youtube-red.svg)](https://www.youtube.com/NXP_Semiconductors)
[![Follow us on LinkedIn](https://img.shields.io/badge/LinkedIn-Follow%20us%20on%20LinkedIn-blue.svg)](https://www.linkedin.com/company/nxp-semiconductors)
[![Follow us on Facebook](https://img.shields.io/badge/Facebook-Follow%20us%20on%20Facebook-blue.svg)](https://www.facebook.com/nxpsemi/)
[![Follow us on Twitter](https://img.shields.io/badge/X-Follow%20us%20on%20X-black.svg)](https://x.com/NXP)

## 7. Release Notes<a name="step7"></a>
| Version | Description / Update                           | Date                        |
|:-------:|------------------------------------------------|----------------------------:|
| 1.0     | Initial release on Application Code Hub        | Sept 27<sup>th</sup> 2024 |

