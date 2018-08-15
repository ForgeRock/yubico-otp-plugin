/*
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
 * Portions copyright 2017 ForgeRock AS.
 */

package org.forgerock.openam.auth.nodes;

import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.shared.debug.Debug;
import com.yubico.client.v2.VerificationResponse;
import com.yubico.client.v2.YubicoClient;
import com.yubico.client.v2.exceptions.YubicoValidationFailure;
import com.yubico.client.v2.exceptions.YubicoVerificationException;

import org.forgerock.guava.common.collect.ImmutableList;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.CoreWrapper;
import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextOutputCallback;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.forgerock.openam.auth.node.api.Action.send;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;


/**
* A KBA node. Asks a random question from self-service KBA questions in user profile.
*
*/
@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class,
       configClass = YubicoRegisterNode.Config.class)
public class YubicoRegisterNode extends SingleOutcomeNode {

   /**
    * Configuration for the node.
    */
   public interface Config {
       //Property to search for
       @Attribute(order = 100)
       default String yubikeyAttribute() {
    	   return "";
       }
       @Attribute(order = 200)
       default Integer clientId() {
    	   return 0;
       }
       @Attribute(order = 300)
       default String secretKey() {
    	   return "";
       }
   }

   private final Config config;
   private final CoreWrapper coreWrapper;
   private final static String DEBUG_FILE = "YubikeyNode";
   protected Debug debug = Debug.getInstance(DEBUG_FILE);

   /**
    * Guice constructor.
    *
    * @param config The service config for the node.
    * @throws NodeProcessException If there is an error reading the configuration.
    */
   @Inject
   public YubicoRegisterNode(@Assisted Config config, CoreWrapper coreWrapper)
           throws NodeProcessException {
       this.config = config;
       this.coreWrapper = coreWrapper;
   }


   @Override
   public Action process(TreeContext context) throws NodeProcessException {
	   // Get configuration values
	   String yubikeyAttribute = config.yubikeyAttribute();
	   Integer clientId = config.clientId();
	   String secretKey = config.secretKey();

	   // If a callback exists then this is a response from a user
       if (context.hasCallbacks()) {
    	   // Get the OTP from the callback
    	   Optional<char[]> otpChars = context.getCallback(PasswordCallback.class).map(PasswordCallback::getPassword);
           String otp = String.valueOf(otpChars.get());
           
           // Validate the OTP against the Yubico service
           YubicoClient client = YubicoClient.getClient(clientId, secretKey);
           VerificationResponse response;
		   try {
			   response = client.verify(otp);
			   if (response.isOk()) {
				   Map<String, Set> attrMap = new HashMap<String, Set>();
				   Set<String> values = new HashSet<String>();
				   values.add(client.getPublicId(otp));
				   attrMap.put(yubikeyAttribute, values);
				   debug.message("[" + DEBUG_FILE + "]: Setting profile attribute " + yubikeyAttribute);
				   AMIdentity userIdentity = coreWrapper.getIdentity(context.sharedState.get(USERNAME).asString(),context.sharedState.get(REALM).asString());
				   userIdentity.setAttributes(attrMap);
				   userIdentity.store();
			   }
		   } catch (YubicoVerificationException | YubicoValidationFailure e) {
				debug.error("[" + DEBUG_FILE + "]: " + " Error validating Yubikey '{}' ", e);
		   } catch (SSOException | IdRepoException e) {
	            debug.error("[" + DEBUG_FILE + "]: " + " Error setting profile atttribute '{}' ", e);
		   }
		   return goToNext().build();
       } 
       else {
    	   TextOutputCallback textCallback = new TextOutputCallback(TextOutputCallback.INFORMATION, "Register your Yubikey here");
    	   PasswordCallback passwordCallback = new PasswordCallback("OTP", false);
    	   ImmutableList<Callback> callbacks = ImmutableList.of(textCallback, passwordCallback);
    	   return send(callbacks).build();
       }
   }

}

