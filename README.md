<!--
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017 ForgeRock AS.
 * Portions copyright 2018 Matthew Ehle.
-->
# Yubico OTP Authentication Plugin  

An authentication plugin for ForgeRock's [Identity Platform][forgerock_platform] 5.5 and above. This plugin contains three nodes related to Yubico OTP:
- Check if a user has registered a Yubikey
- Register a Yubikey
- Validate a Yubikey OTP

## Installation
Copy the .jar file from the ../target directory into the ../web-container/webapps/openam/WEB-INF/lib directory where AM is deployed.  Restart the web container to pick up the new plugin.  The plugin will then appear in the authentication trees components palette.

## Usage

The node uses KBAs defined in a user's profile by the user self-service module. Enable the self-service module and allow a user to register one or questions during registration or in their profile page. This node will then pick a random question from the profile and prompt for the answer. The node outcome is either true or false depending on the users response.

## To Build
The code in this repository has binary dependencies that live in the ForgeRock maven repository. Maven can be configured to authenticate to this repository by following the following [ForgeRock Knowledge Base Article](https://backstage.forgerock.com/knowledge/kb/article/a74096897).

The code also has dependencies on the freely available Yubico OTP library. This will be packaged by default when building the plugin.

To rebuild, run "mvn clean install" in the directory containing the pom.xml    

## Disclaimer

The sample code described herein is provided on an "as is" basis, without warranty of any kind, to the fullest extent permitted by law. ForgeRock does not warrant or guarantee the individual success developers may have in implementing the sample code on their development platforms or in production configurations.

ForgeRock does not warrant, guarantee or make any representations regarding the use, results of use, accuracy, timeliness or completeness of any data or information relating to the sample code. ForgeRock disclaims all warranties, expressed or implied, and in particular, disclaims all warranties of merchantability, and warranties related to the code, or any service or software related thereto.

ForgeRock shall not be liable for any direct, indirect or consequential damages or costs of any type arising out of any action taken by you or others related to the sample code.

[forgerock_platform]: https://www.forgerock.com/platform/  

