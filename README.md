Jenkins Login Rate Limiter Plugin
=================================

This plugin limits the number of login attempts for specific user accounts to prevent brute-forcing users' passwords.

Configuration
-------------

The rate limiter uses a time span of ten minutes (600 seconds) and three attempts by default. These values can be changed using the following system properties:

* `org.jenkinsci.plugins.loginratelimiter.LoginRateLimiter.duration` specifies how far back to check for login failures, in seconds.
* `org.jenkinsci.plugins.loginratelimiter.LoginRateLimiter.attempts` specifies how many attempts are allowed in the given time span.

Example command line:

    java -jar jenkins.war -Dorg.jenkinsci.plugins.loginratelimiter.LoginRateLimiter.duration=60 -Dorg.jenkinsci.plugins.loginratelimiter.LoginRateLimiter.attempts=1

This limits the number of attempts to log in as a certain user to *1* per *60 seconds*, i.e. a user has to wait 60 seconds before attempting another login when entering a wrong password *once*. Even login attempts with the correct password count as failed during this time span.

Logging
-------

This plugin logs to `jenkins.security.SecurityListener`. Levels used are:

* `WARNING` when a user is denied access due to the rate limiter (which only happens upon entering correct credentials).

* `FINE` otherwise.
