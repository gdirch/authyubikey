<?php
/**
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 *
 * @author     Dirk Scheer <dirk@scheernet.de>
 */

$meta['yubico_client_id']  = array('numeric');
$meta['yubico_secret_key'] = array('string', '_pattern' => '..*');
$meta['yubico_maxkeys']    = array('multichoice', '_choices' => array(1,2,3,4,5));
