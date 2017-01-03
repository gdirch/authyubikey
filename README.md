authyubikey
===========
This plugin is written for Dokuwiki to enable a two factor authentification.


Prerequisites
=============
You have to ensure, that your PHP installation supports PEAR and curl (i.e. php-pear and php5-curl on Debian systems).


Install
=======
This plugin can be installed manually in the plugin directory of Dokuwiki
(i.e. /usr/share/dokuwiki/lib/plugins).

After that, you have to login into your Dokuwiki as an administrator. At first
you have to configure the new authentification method in the configuration form
of Dokuwiki by choosing "authyubikey" as Dokuwiki's "authtype".

Moreover it is important, that the users can manage their own profiles. So do not
disable "User profile" with the parameter "disableactions".

In the next step you have to set client ID and the secret key for your Yubikey.
If you do not know, what this mean, please vist https://upgrade.yubico.com/getapikey
and follow their instructions.

After that you have to decide, how many different Yubikey-OTP's a user can manage.

Now users can add their personal Yubikeys in personal profile form (see also
https://your.domain.org/dokuwiki/doku.php?id=start&do=profile).
