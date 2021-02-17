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
 * Portions copyright 2018 Matthew Ehle.
 */


package org.forgerock.openam.auth.nodes;

import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.shared.debug.Debug;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.CoreWrapper;
import javax.inject.Inject;
import java.util.Set;

import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;


/**
* Registered Yubikey presence node. Detects whether a user has already registered their Yubikey.
*
*/
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class,
       configClass = YubicoPresenceNode.Config.class)
public class YubicoPresenceNode extends AbstractDecisionNode {

   /**
    * Configuration for the node.
    */
   public interface Config {
       //Property to search for
       @Attribute(order = 100)
       default String yubikeyAttribute() {
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
   public YubicoPresenceNode(@Assisted Config config, CoreWrapper coreWrapper)
           throws NodeProcessException {
       this.config = config;
       this.coreWrapper = coreWrapper;
   }


   @Override
   public Action process(TreeContext context) throws NodeProcessException {
	   // Get configuration values
	   String yubikeyAttribute = config.yubikeyAttribute();

       // See if the user has a Yubikey attribute
       AMIdentity userIdentity = coreWrapper.getIdentity(context.sharedState.get(USERNAME).asString(),context.sharedState.get(REALM).asString());
       debug.message("[" + DEBUG_FILE + "]: Looking for profile attribute " + yubikeyAttribute);
       try {
           Set<String> idAttrs = userIdentity.getAttribute(yubikeyAttribute);
           if (idAttrs == null || idAttrs.isEmpty()) {
               debug.message("[" + DEBUG_FILE + "]: " + "User does not have a registered Yubikey");
               return goTo(false).build();
           } else {
        	   debug.message("[" + DEBUG_FILE + "]: " + "User has a registered Yubikey");
        	   return goTo(true).build();
           }
       } catch (IdRepoException e) {
           debug.error("[" + DEBUG_FILE + "]: " + " Error retrieving attribute '{}' ", e);
       } catch (SSOException e) {
           debug.error("[" + DEBUG_FILE + "]: " + "Node exception", e);
       }
       return goTo(false).build();
   }

}

