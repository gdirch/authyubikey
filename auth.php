<?php
/**
 * DokuWiki Plugin authyubikey (Auth Component)
 * Plaintext authentication backend combined with Yubico's OTP
 *
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     Dirk Scheer <dirk@scheernet.de>
 */

// This lib is developed by Yubico.
// Take a look at https://developers.yubico.com/php-yubico/
require_once 'lib/Yubico.php';

// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

/*
 * Class auth_plugin_authyubikey simply extends the
 * auth_plugin_authplain class definition.
 */
class auth_plugin_authyubikey extends auth_plugin_authplain {
    /**
     * Constructor
     *
     * Carry out sanity checks to ensure the object is
     * able to operate. Set capabilities.
     *
     * @author  Dirk Scheer <dirk@scheernet.de>
     */
    public function __construct() {
        parent::__construct();
    }

    /**
     * Check user+password
     *
     * Checks if the given user exists and the given
     * plaintext password is correct
     *
     * @author  Dirk Scheer <dirk@scheernet.de>
     * @param string $user
     * @param string $pass
     * @return  bool
     */
    public function checkPass($user, $pass) {
        global $INPUT;
        global $config;

        /* Get all defined users with their attributes */
        $userinfo = $this->getUserData($user);
        if($userinfo === false) return false;

        /* Check the given password */
        if(auth_verifyPassword($pass, $this->users[$user]['pass']) === false) return false;

        /* If this function is called in another context as the login form;
         * then checking of the password is enough.
         * (I hope, this is not a security risc!!!)
         */
        if($INPUT->str('do') !== 'login') {
            return true;
        }

        /* Get the yubikey IDs of the user. If the user has no IDs,
         * no further checking is needed for this user.
         */
        $yubikeys = $this->users[$user]['yubi'];
        if(count($yubikeys) === 0) return true;

        /* Get the one-time password, the user has entered
         * in the login form. From this OTP we have to extract the
         * first 12 bytes. These bytes build the ID of the key, which
         * is stored in the yubikey-mapping file.
         */
        $otp = $INPUT->str('otp');
        $yid = substr($otp, 0, 12);
        if(in_array($yid, $yubikeys) === false) return false;

        /* A corresponding Yubikey ID was found, so we will check
         * finally the entered OTP against the servers of Yubico.
         */
        $yubi = new Auth_Yubico($this->getConf('yubico_client_id'), $this->getConf('yubico_secret_key'));
        $auth = $yubi->verify($otp);
        return (PEAR::isError($auth) ? false : true);
    }

    /**
     * Modify user data
     *
     * @author  Dirk Scheer <dirk@scheernet.de>
     * @author  Chris Smith <chris@jalakai.co.uk>
     * @param   string $user      nick of the user to be changed
     * @param   array  $changes   array of field/value pairs to be changed (password will be clear text)
     * @return  bool
     */
    public function modifyUser($user, $changes) {
        global $ACT;
        global $INPUT;
        global $conf;
        global $config_cascade;

        // sanity checks, user must already exist and there must be something to change
        if(($userinfo = $this->getUserData($user)) === false) return false;
        if(!is_array($changes) || !count($changes)) return true;

        // update userinfo with new data, remembering to encrypt any password
        $newuser = $user;
        foreach($changes as $field => $value) {
            if($field == 'user') {
                $newuser = $value;
                continue;
            }
            if($field == 'pass') $value = auth_cryptPassword($value);
            $userinfo[$field] = $value;
        }

        // Check all entered Yubikeys
        $yubi   = new Auth_Yubico($this->getConf('yubico_client_id'), $this->getConf('yubico_secret_key'));
        $errors = array();
        $userinfo['yubi'] = array();
        for($i=0; $i < intval($this->getConf('yubico_maxkeys')); $i++) {
            $otp = $INPUT->str('yubikeyid'.$i);
            if($otp !== '') {
                if($otp == $this->users[$user]['yubi'][$i]) {
                    array_push($userinfo['yubi'], substr($otp, 0, 12));
                }
                else {
                    $auth = $yubi->verify($otp);
                    if(PEAR::isError($auth) && $auth != 'REPLAYED_OTP') {
                        if($this->getConf('yubico_maxkeys') == 1) {
                            array_push($errors, sprintf($this->getLang('yubikeyiderr'), substr($otp, 0, 12), $auth));
                        }
                        else {
                            array_push($errors, sprintf($this->getLang('yubikeyidserr'), $i+1, substr($otp, 0, 12), $auth));
                        }
                    }
                    else {
                        array_push($userinfo['yubi'], substr($otp, 0, 12));
                    }
                }
            }
        }
        if(count($errors) > 0) {
            foreach($errors as $error) {
                $errtext .= $error . '<BR>';
            }
            msg($errtext, -1);
            return false;
        }

        $userline = $this->_createUserLine($newuser, $userinfo['pass'], $userinfo['name'], $userinfo['mail'], $userinfo['grps']);

        if(!$this->deleteUsers(array($user))) {
            msg('Unable to modify user data. Please inform the Wiki-Admin', -1);
            return false;
        }

        if(!io_saveFile($config_cascade['plainauth.users']['default'], $userline, true)) {
            msg('There was an error modifying your user data. You should register again.', -1);
            // FIXME, user has been deleted but not recreated, should force a logout and redirect to login page
            $ACT = 'register';
            return false;
        }

        $yubiline = '';
        foreach($userinfo['yubi'] as $yubi) {
            $yubiline .= $newuser . ':' . $yubi . "\n";
        }
        if(!io_saveFile(DOKU_CONF . 'users.yubikeys.php', $yubiline, true)) {
            msg('There was an error saving your Yubikey ID\'s. You should try again.', -1);
            return false;
        }
 
        $this->users[$newuser] = $userinfo;
        return true;
    }

    /**
     * Remove one or more users from the list of registered users
     *
     * @author  Dirk Scheer <dirk@scheernet.de>
     * @author  Christopher Smith <chris@jalakai.co.uk>
     * @param   array  $users   array of users to be deleted
     * @return  int             the number of users deleted
     */
    public function deleteUsers($users) {
        global $config_cascade;

        if(!is_array($users) || empty($users)) return 0;

        if($this->users === null) $this->_loadUserData();

        $deleted = array();
        foreach($users as $user) {
            if(isset($this->users[$user])) $deleted[] = preg_quote($user, '/');
        }

        if(empty($deleted)) return 0;

        $pattern = '/^('.join('|', $deleted).'):/';
        io_deleteFromFile($config_cascade['plainauth.users']['default'], $pattern, true);
        io_deleteFromFile(DOKU_CONF . 'users.yubikeys.php', $pattern, true);

        // reload the user list and count the difference
        $count = count($this->users);
        $this->_loadUserData();
        $count -= count($this->users);
        return $count;
    }

    /**
     * Load all user data
     *
     * loads the user file into a datastructure
     *
     * @author  Dirk Scheer <dirk@scheernet.de>
     * @author  Andreas Gohr <andi@splitbrain.org>
     */
    protected function _loadUserData() {
        global $config_cascade;

        $this->users = array();

        if(!@file_exists($config_cascade['plainauth.users']['default'])) return;

        $lines = file($config_cascade['plainauth.users']['default']);
        foreach($lines as $line) {
            $line = preg_replace('/#.*$/', '', $line); //ignore comments
            $line = trim($line);
            if(empty($line)) continue;

            /* NB: preg_split can be deprecated/replaced with str_getcsv once dokuwiki is min php 5.3 */
            $row = $this->_splitUserData($line);
            $row = str_replace('\\:', ':', $row);
            $row = str_replace('\\\\', '\\', $row);

            $groups = array_values(array_filter(explode(",", $row[4])));

            $this->users[$row[0]]['pass'] = $row[1];
            $this->users[$row[0]]['name'] = urldecode($row[2]);
            $this->users[$row[0]]['mail'] = $row[3];
            $this->users[$row[0]]['grps'] = $groups;
            $this->users[$row[0]]['yubi'] = array();
        }

        /* Read the mapping table for Yubikeys */
        $lines = file(DOKU_CONF . 'users.yubikeys.php');
        foreach($lines as $line) {
            $line = preg_replace('/#.*$/', '', $line); //ignore comments
            $line = trim($line);
            if(empty($line)) continue;

            list($user, $yubikey) = explode(':', $line);
            if(isset($this->users[$user])) {
                array_push($this->users[$user]['yubi'], $yubikey);
            }
        }
    }
}
