<?php
/**
 * DokuWiki Plugin authyubikey (Action Component)
 * Plaintext authentication backend combined with Yubico's OTP
 *
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     Dirk Scheer <dirk@scheernet.de>
 */

// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

/**
 * Class action_plugin_authyubikey
 */
class action_plugin_authyubikey extends DokuWiki_Action_Plugin {

    /**
     * Registring
     *
     * Registers a callback function for a given event
     *
     * @author   Dirk Scheer <dirk@scheernet.de>
     * @param    Doku_Event_Handler
     *
     */
    public function register(Doku_Event_Handler &$controller) {

        $controller->register_hook('HTML_LOGINFORM_OUTPUT', 'BEFORE', $this, 'handle_loginform');
        $controller->register_hook('HTML_UPDATEPROFILEFORM_OUTPUT', 'BEFORE', $this, 'handle_updateprofileform');

    }


    /**
     * Hook for the login form
     *
     * Shows a one-time password field in the login form
     *
     * @author   Dirk Scheer <dirk@scheernet.de>
     * @param Doku_Event $event
     * @param array      $param
     */
    public function handle_loginform(Doku_Event &$event, $param) {
        /** Get a reference to $form */
        $form =& $event->data;

        // add select box
        $element = form_makeTextField('otp', '', $this->getLang('otp'), '', 'block');
        $pos     = $form->findElementByAttribute('name', 'p');
        $form->insertElement($pos + 1, $element);
    }




    /**
     * Hook for the profile form
     *
     * Shows Yubikey ID fields in the personal profile form
     *
     * @author   Dirk Scheer <dirk@scheernet.de>
     * @param Doku_Event $event
     * @param array      $param
     */
    public function handle_updateprofileform(Doku_Event &$event, $param) {
        global $INPUT;
        global $auth;
        global $conf;

        /** Get a reference to $form */
        $form =& $event->data;
        $pos   = $form->findElementByAttribute('name', 'login');
        $elem =& $form->getElementAt($pos);
        $user  = $elem['value'];

        $yubi = array();
        if($user !== '') {
            $userinfo = $auth->getUserData($user);
            if($userinfo === false) return false;
            $yubi = $userinfo['yubi'];
        }

        // add textboxes for entering the Yubikey ID's
        $maxkeys = $this->getConf('yubico_maxkeys');
        for($i=0 ; $i<$maxkeys ; $i++) {
            /* Building the label - if the user can enter
             * enter only one ID, then the ID's are not
             * numbered.
            */
            if($maxkeys == 1) {
               $label = $this->getLang('yubikeyid');
            }
            else {
               $label = $this->getLang('yubikeyid') . ' #' . ($i+1);
            }
            /* Is there a value already defined in the $_POST environment?
             * If not, then we will use the value stored value.
            */
            $value = $INPUT->str('yubikeyid'.$i);
            if($value === '') {
                $value = $yubi[$i];
            }
            $element = form_makeTextField('yubikeyid'.$i, $value, $label, '', 'block', array('maxlength'=>'44'));
            $pos     = $form->findElementByAttribute('name', 'email');
            $form->insertElement($pos + $i + 1, $element);
        }
    }
}

// vim:ts=4:sw=4:et:
